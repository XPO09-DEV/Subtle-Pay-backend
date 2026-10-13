import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { db, withTransaction, type UserRow } from "../../db.js";
import { generateAccountId, isValidAccountId, normalizeAccountId, newId, sha256Hex } from "../../lib/crypto.js";
import { assertNotLocked, hashPassword, needsRehash, recordLoginFailure, recordLoginSuccess, validatePasswordPolicy, verifyPassword, verifyPasswordDummy } from "../../lib/password.js";
import { issueSession, revokeAllSessions, type SessionMeta } from "../../lib/tokens.js";
import { encryptSecret, zeroize } from "../../lib/kms.js";
import { badRequest, invalidCredentials } from "../../lib/errors.js";
import { assertCurrency, type Currency } from "../../lib/currency.js";
import { audit } from "../../lib/audit.js";
import { createPayQrPayload } from "../../lib/paymentQr.js";

function recordLoginEvent(input: {
  accountId: string | null; attemptedId: string; success: boolean;
  reason: "success" | "invalid_credentials" | "account_locked" | "registration"; meta: SessionMeta;
}): void {
  try {
    db.prepare(`INSERT INTO login_events (id, account_id, subject_hash, success, reason, ip, user_agent, request_id, event_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(newId(), input.accountId, sha256Hex(normalizeAccountId(input.attemptedId)), input.success ? 1 : 0, input.reason,
        input.meta.ip ?? null, input.meta.userAgent?.slice(0, 512) ?? null, input.meta.requestId?.slice(0, 128) ?? null, Date.now());
  } catch {
    // Authentication outcome must not be changed by the tracking subsystem.
  }
}
/** One custodial wallet per account. The raw key is wiped before this returns. */
function createWallet(userId: string): string {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const secret = Buffer.from(privateKey.slice(2), "hex");
  try {
    const blob = encryptSecret(secret, { userId, address: account.address });
    db.prepare("INSERT INTO wallets (user_id, address, enc_priv_key, kek_version, created_at) VALUES (?, ?, ?, 1, ?)")
      .run(userId, account.address, blob, Date.now());
    return account.address;
  } finally { zeroize(secret); }
}
export async function register(password: string, meta: SessionMeta) {
  validatePasswordPolicy(password);
  const accountId = generateAccountId();
  const passwordHash = await hashPassword(password);
  const now = Date.now();
  const address = withTransaction(() => {
    db.prepare("INSERT INTO users (id, password_hash, currency, created_at, updated_at) VALUES (?, ?, 'USD', ?, ?)")
      .run(accountId, passwordHash, now, now);
    const walletAddress = createWallet(accountId);
    // Issue and persist this wallet's permanent receive QR at account creation.
    db.prepare("INSERT INTO wallet_qr (user_id, payload, chain_id, created_at) VALUES (?, ?, 10143, ?)")
      .run(accountId, createPayQrPayload(walletAddress), now);
    return walletAddress;
  });
  const session = await issueSession(accountId, meta);
  recordLoginEvent({ accountId, attemptedId: accountId, success: true, reason: "registration", meta });
  audit(accountId, "auth.register", undefined, meta.ip);
  return { accountId, token: session.accessToken, refreshToken: session.refreshToken, expiresIn: session.accessTokenExpiresIn, address };
}
export async function login(accountIdRaw: string, password: string, meta: SessionMeta) {
  const accountId = normalizeAccountId(accountIdRaw);
  if (!isValidAccountId(accountId)) {
    await verifyPasswordDummy(password);
    recordLoginEvent({ accountId: null, attemptedId: accountIdRaw, success: false, reason: "invalid_credentials", meta });
    audit(null, "auth.login_failed", { reason: "invalid_credentials" }, meta.ip);
    throw invalidCredentials();
  }
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND deleted_at IS NULL").get(accountId) as UserRow | undefined;
  if (!user) {
    await verifyPasswordDummy(password);
    recordLoginEvent({ accountId: null, attemptedId: accountIdRaw, success: false, reason: "invalid_credentials", meta });
    audit(null, "auth.login_failed", { reason: "invalid_credentials" }, meta.ip);
    throw invalidCredentials();
  }
  try { assertNotLocked(user.locked_until); }
  catch {
    recordLoginEvent({ accountId: user.id, attemptedId: accountIdRaw, success: false, reason: "account_locked", meta });
    audit(user.id, "auth.login_failed", { reason: "account_locked" }, meta.ip);
    throw invalidCredentials();
  }
  const ok = await verifyPassword(user.password_hash, password);
  if (!ok) {
    const failure = recordLoginFailure(user.id);
    recordLoginEvent({ accountId: user.id, attemptedId: accountIdRaw, success: false, reason: "invalid_credentials", meta });
    audit(user.id, "auth.login_failed", { attempts: failure.attempts, reason: "invalid_credentials" }, meta.ip);
    throw invalidCredentials();
  }
  recordLoginSuccess(user.id);
  recordLoginEvent({ accountId: user.id, attemptedId: accountIdRaw, success: true, reason: "success", meta });
  if (await needsRehash(user.password_hash)) {
    const next = await hashPassword(password);
    db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(next, Date.now(), user.id);
  }
  const session = await issueSession(user.id, meta);
  audit(user.id, "auth.login", undefined, meta.ip);
  return { token: session.accessToken, refreshToken: session.refreshToken, expiresIn: session.accessTokenExpiresIn };
}
export async function changePassword(userId: string, sessionId: string, oldPassword: string, newPassword: string, ip?: string) {
  validatePasswordPolicy(newPassword, userId);
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId) as UserRow | undefined;
  if (!user) throw invalidCredentials();
  const ok = await verifyPassword(user.password_hash, oldPassword);
  if (!ok) throw badRequest("Current password is wrong", "INVALID_CREDENTIALS");
  if (oldPassword === newPassword) throw badRequest("Choose a different password");
  const next = await hashPassword(newPassword);
  db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(next, Date.now(), userId);
  revokeAllSessions(userId, sessionId);
  audit(userId, "auth.password_changed", undefined, ip);
  return { ok: true };
}
export function getMe(userId: string) {
  const user = db.prepare("SELECT id, currency, display_name, region, region_consent_at, created_at FROM users WHERE id = ? AND deleted_at IS NULL").get(userId) as
    | { id: string; currency: string; display_name: string | null; region: string | null; region_consent_at: number | null; created_at: number } | undefined;
  if (!user) throw invalidCredentials();
  const alias = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
  const wallet = db.prepare("SELECT address, created_at FROM wallets WHERE user_id = ?").get(userId) as { address: string; created_at: number } | undefined;
  const lastLogin = db.prepare(`SELECT COALESCE(
    (SELECT MAX(event_at) FROM login_events WHERE account_id = ? AND success = 1 AND reason = 'success'),
    (SELECT MAX(ts) FROM audit_log WHERE actor = ? AND action = 'auth.login')
  ) AS last_login_at`).get(userId, userId) as { last_login_at: number | null } | undefined;
  return {
    accountId: user.id, alias: alias?.alias ?? null, displayName: user.display_name, currency: user.currency,
    accountCreatedAt: user.created_at, lastLoginAt: lastLogin?.last_login_at ?? null,
    walletAddress: wallet?.address ?? null, walletCreatedAt: wallet?.created_at ?? null,
    region: user.region_consent_at ? user.region : null, regionConsentAt: user.region_consent_at,
  };
}
export function updateProfile(userId: string, input: { displayName?: string | null; region?: string | null; shareRegion?: boolean }) {
  const existing = db.prepare("SELECT display_name, region, region_consent_at FROM users WHERE id = ?").get(userId) as
    | { display_name: string | null; region: string | null; region_consent_at: number | null } | undefined;
  if (!existing) throw invalidCredentials();
  let displayName = existing.display_name;
  if (input.displayName !== undefined) { const cleaned = input.displayName?.trim().slice(0, 80) ?? ""; displayName = cleaned || null; }
  let region = existing.region;
  let regionConsentAt = existing.region_consent_at;
  if (input.shareRegion === true) {
    const cleanedRegion = input.region?.trim().slice(0, 80);
    if (!cleanedRegion) throw badRequest("Choose a region before opting in to share it", "BAD_REQUEST");
    region = cleanedRegion; regionConsentAt = Date.now();
  } else if (input.shareRegion === false) { region = null; regionConsentAt = null; }
  db.prepare("UPDATE users SET display_name = ?, region = ?, region_consent_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL")
    .run(displayName, region, regionConsentAt, Date.now(), userId);

  // A human-readable handle is assigned once on the first profile-name save.
  // Existing handles are never changed by editing the display name.
  let aliasRow = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
  if (!aliasRow && displayName) {
    const reserved = new Set(["admin", "support", "subtle", "subtlepay", "monad", "system", "root"]);
    let base = displayName.normalize("NFKD").replace(/[\\u0300-\\u036f]/g, "").trim().split(/\\s+/)[0]?.toLowerCase().replace(/[^a-z0-9_]/g, "") ?? "";
    if (base.length < 3 || reserved.has(base)) base = ("user" + userId.replace(/[^a-z0-9]/gi, "").slice(-8)).toLowerCase();
    base = base.slice(0, 20);
    for (let index = 1; index <= 9999; index++) {
      const suffix = index === 1 ? "" : String(index);
      const candidate = base.slice(0, 20 - suffix.length) + suffix;
      const taken = db.prepare("SELECT 1 FROM aliases WHERE alias = ?").get(candidate);
      if (!taken && !reserved.has(candidate)) {
        db.prepare("INSERT INTO aliases (alias, user_id, created_at) VALUES (?, ?, ?)").run(candidate, userId, Date.now());
        aliasRow = { alias: candidate };
        break;
      }
    }
  }
  return { displayName, alias: aliasRow?.alias ?? null, region: regionConsentAt ? region : null, regionConsentAt };
}
export function setCurrency(userId: string, currency: string): { currency: Currency } {
  const code = assertCurrency(currency);
  db.prepare("UPDATE users SET currency = ?, updated_at = ? WHERE id = ?").run(code, Date.now(), userId);
  return { currency: code };
}
