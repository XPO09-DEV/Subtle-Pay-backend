import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { db, withTransaction, type UserRow } from "../../db.js";
import { generateAccountId, isValidAccountId, normalizeAccountId } from "../../lib/crypto.js";
import {
  assertNotLocked,
  hashPassword,
  needsRehash,
  recordLoginFailure,
  recordLoginSuccess,
  validatePasswordPolicy,
  verifyPassword,
  verifyPasswordDummy,
} from "../../lib/password.js";
import { issueSession, revokeAllSessions, type SessionMeta } from "../../lib/tokens.js";
import { encryptSecret, zeroize } from "../../lib/kms.js";
import { badRequest, invalidCredentials } from "../../lib/errors.js";
import { assertCurrency, type Currency } from "../../lib/currency.js";
import { audit } from "../../lib/audit.js";

/** One custodial wallet per account. The raw key is wiped before this returns. */
function createWallet(userId: string): string {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const secret = Buffer.from(privateKey.slice(2), "hex");
  try {
    const blob = encryptSecret(secret, { userId, address: account.address });
    db.prepare(
      `INSERT INTO wallets (user_id, address, enc_priv_key, kek_version, created_at)
       VALUES (?, ?, ?, 1, ?)`
    ).run(userId, account.address, blob, Date.now());
    return account.address;
  } finally {
    zeroize(secret);
  }
}

export async function register(password: string, meta: SessionMeta) {
  validatePasswordPolicy(password);
  const accountId = generateAccountId();
  const passwordHash = await hashPassword(password);
  const now = Date.now();

  const address = withTransaction(() => {
    db.prepare(
      `INSERT INTO users (id, password_hash, currency, created_at, updated_at)
       VALUES (?, ?, 'USD', ?, ?)`
    ).run(accountId, passwordHash, now, now);
    return createWallet(accountId);
  });

  const session = await issueSession(accountId, meta);
  audit(accountId, "auth.register", undefined, meta.ip);

  return {
    accountId,
    token: session.accessToken,
    refreshToken: session.refreshToken,
    expiresIn: session.accessTokenExpiresIn,
    address,
  };
}

export async function login(accountIdRaw: string, password: string, meta: SessionMeta) {
  const accountId = normalizeAccountId(accountIdRaw);
  if (!isValidAccountId(accountId)) {
    await verifyPasswordDummy(password);
    throw invalidCredentials();
  }

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(accountId) as UserRow | undefined;
  if (!user) {
    await verifyPasswordDummy(password);
    throw invalidCredentials();
  }

  assertNotLocked(user.locked_until);
  const ok = await verifyPassword(user.password_hash, password);
  if (!ok) {
    const failure = recordLoginFailure(user.id);
    audit(user.id, "auth.login_failed", { attempts: failure.attempts }, meta.ip);
    if (failure.lockedUntil) assertNotLocked(failure.lockedUntil);
    throw invalidCredentials();
  }

  recordLoginSuccess(user.id);
  if (await needsRehash(user.password_hash)) {
    const next = await hashPassword(password);
    db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(
      next,
      Date.now(),
      user.id
    );
  }

  const session = await issueSession(user.id, meta);
  audit(user.id, "auth.login", undefined, meta.ip);
  return {
    token: session.accessToken,
    refreshToken: session.refreshToken,
    expiresIn: session.accessTokenExpiresIn,
  };
}

export async function changePassword(
  userId: string,
  sessionId: string,
  oldPassword: string,
  newPassword: string,
  ip?: string
) {
  validatePasswordPolicy(newPassword, userId);
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId) as UserRow | undefined;
  if (!user) throw invalidCredentials();
  const ok = await verifyPassword(user.password_hash, oldPassword);
  if (!ok) throw badRequest("Current password is wrong", "INVALID_CREDENTIALS");
  if (oldPassword === newPassword) throw badRequest("Choose a different password");

  const next = await hashPassword(newPassword);
  db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(
    next,
    Date.now(),
    userId
  );
  revokeAllSessions(userId, sessionId);
  audit(userId, "auth.password_changed", undefined, ip);
  return { ok: true };
}

export function getMe(userId: string) {
  const user = db.prepare("SELECT id, currency, display_name, region, region_consent_at, created_at FROM users WHERE id = ?").get(userId) as
    | { id: string; currency: string; display_name: string | null; region: string | null; region_consent_at: number | null; created_at: number }
    | undefined;
  if (!user) throw invalidCredentials();
  const alias = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as
    | { alias: string }
    | undefined;
  const wallet = db.prepare("SELECT address, created_at FROM wallets WHERE user_id = ?").get(userId) as
    | { address: string; created_at: number }
    | undefined;
  const lastLogin = db.prepare(
    "SELECT MAX(ts) AS last_login_at FROM audit_log WHERE actor = ? AND action = 'auth.login'"
  ).get(userId) as { last_login_at: number | null } | undefined;
  return {
    accountId: user.id,
    alias: alias?.alias ?? null,
    displayName: user.display_name,
    currency: user.currency,
    accountCreatedAt: user.created_at,
    lastLoginAt: lastLogin?.last_login_at ?? null,
    walletAddress: wallet?.address ?? null,
    walletCreatedAt: wallet?.created_at ?? null,
    region: user.region_consent_at ? user.region : null,
    regionConsentAt: user.region_consent_at,
  };
}

export function updateProfile(
  userId: string,
  input: { displayName?: string | null; region?: string | null; shareRegion?: boolean }
) {
  const existing = db.prepare(
    "SELECT display_name, region, region_consent_at FROM users WHERE id = ?"
  ).get(userId) as
    | { display_name: string | null; region: string | null; region_consent_at: number | null }
    | undefined;
  if (!existing) throw invalidCredentials();

  let displayName = existing.display_name;
  if (input.displayName !== undefined) {
    const cleaned = input.displayName?.trim().slice(0, 80) ?? "";
    displayName = cleaned || null;
  }

  let region = existing.region;
  let regionConsentAt = existing.region_consent_at;
  if (input.shareRegion === true) {
    const cleanedRegion = input.region?.trim().slice(0, 80);
    if (!cleanedRegion) throw badRequest("Choose a region before opting in to share it", "BAD_REQUEST");
    region = cleanedRegion;
    regionConsentAt = Date.now();
  } else if (input.shareRegion === false) {
    region = null;
    regionConsentAt = null;
  }

  db.prepare(
    "UPDATE users SET display_name = ?, region = ?, region_consent_at = ?, updated_at = ? WHERE id = ?"
  ).run(displayName, region, regionConsentAt, Date.now(), userId);

  return { displayName, region: regionConsentAt ? region : null, regionConsentAt };
}

export function setCurrency(userId: string, currency: string): { currency: Currency } {
  const code = assertCurrency(currency);
  db.prepare("UPDATE users SET currency = ?, updated_at = ? WHERE id = ?").run(code, Date.now(), userId);
  return { currency: code };
}