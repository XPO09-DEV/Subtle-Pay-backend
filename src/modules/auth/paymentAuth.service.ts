import * as argon2 from "argon2";
import { config } from "../../config.js";
import { db, withTransaction } from "../../db.js";
import { randomToken, sha256Hex } from "../../lib/crypto.js";
import { audit } from "../../lib/audit.js";
import { badRequest, unauthorized, tooManyRequests } from "../../lib/errors.js";
import { verifyPassword } from "../../lib/password.js";
import { assertCurrency, parseAmountMinor, parseUsdToMicro } from "../../lib/currency.js";

const pinPepper = Buffer.from(config.PASSWORD_PEPPER, "hex");
const pinOptions = {
  type: argon2.argon2id,
  memoryCost: config.ARGON2_MEMORY_KIB,
  timeCost: config.ARGON2_TIME_COST,
  parallelism: config.ARGON2_PARALLELISM,
  secret: pinPepper,
} as const;

export function getMpinStatus(userId: string) {
  return { enabled: db.prepare("SELECT 1 FROM pin_credentials WHERE user_id = ?").get(userId) !== undefined };
}

export async function setMpin(userId: string, currentPassword: string, pin: string, ip?: string) {
  if (!/^\d{6}$/.test(pin)) throw badRequest("MPIN must be exactly six digits.", "INVALID_MPIN");
  const user = db.prepare("SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL")
    .get(userId) as { password_hash: string } | undefined;
  if (!user || !(await verifyPassword(user.password_hash, currentPassword))) {
    audit(userId, "security.mpin_setup_failed", { reason: "invalid_password" }, ip);
    throw unauthorized("Current password is incorrect.", "INVALID_CREDENTIALS");
  }
  const hash = await argon2.hash(pin, pinOptions);
  const now = Date.now();
  db.prepare(`INSERT INTO pin_credentials (user_id, pin_hash, failed_attempts, locked_until, created_at, updated_at)
    VALUES (?, ?, 0, NULL, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET pin_hash = excluded.pin_hash, failed_attempts = 0, locked_until = NULL, updated_at = excluded.updated_at`)
    .run(userId, hash, now, now);
  audit(userId, "security.mpin_enabled", undefined, ip);
  return { enabled: true };
}

export async function removeMpin(userId: string, currentPassword: string, ip?: string) {
  const user = db.prepare("SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL")
    .get(userId) as { password_hash: string } | undefined;
  if (!user || !(await verifyPassword(user.password_hash, currentPassword))) {
    throw unauthorized("Current password is incorrect.", "INVALID_CREDENTIALS");
  }
  db.prepare("DELETE FROM pin_credentials WHERE user_id = ?").run(userId);
  audit(userId, "security.mpin_disabled", undefined, ip);
  return { enabled: false };
}

export type PaymentIntent = {
  to: string;
  amount: string | number;
  amountCurrency: string;
  note?: string;
  asset?: string;
};

function validatePaymentIntent(intent: PaymentIntent): void {
  if (!intent.to.trim() || intent.to.trim().length > 64) {
    throw badRequest("A valid recipient and positive amount are required for payment authorization.");
  }
  const currency = assertCurrency(intent.amountCurrency);
  const amountText = String(intent.amount).trim();
  const amountUnits = currency === "USD" ? parseUsdToMicro(amountText) : parseAmountMinor(amountText, currency);
  if (!Number.isSafeInteger(amountUnits) || amountUnits <= 0) {
    throw badRequest("A valid recipient and positive amount are required for payment authorization.");
  }
  if (intent.note && intent.note.length > 140) throw badRequest("Note is too long.");
  const asset = (intent.asset ?? "MON").trim().toUpperCase();
  if (asset !== "MON" && !(asset === "USDC" && config.STABLE_TOKEN_ADDRESS)) {
    throw badRequest("Only MON and configured USDC on Monad Testnet can be used for payment.");
  }
}

function paymentIntentHash(intent: PaymentIntent): string {
  return sha256Hex(JSON.stringify({
    to: intent.to.trim().toLowerCase(),
    amount: String(intent.amount).trim(),
    amountCurrency: intent.amountCurrency.trim().toUpperCase(),
    note: intent.note?.trim() ?? "",
    asset: (intent.asset ?? "MON").trim().toUpperCase(),
  }));
}

/** Validate once and use this hash on the challenge and the one-time payment token. */
export function getPaymentIntentHash(intent: PaymentIntent): string {
  validatePaymentIntent(intent);
  return paymentIntentHash(intent);
}

/** Called only after a fresh, verified WebAuthn assertion bound to this exact intent. */
export function issuePasskeyPaymentAuthorizationForIntent(userId: string, intentHash: string, ip?: string): { authorizationToken: string; expiresIn: number } {
  if (!/^[a-f0-9]{64}$/.test(intentHash)) throw unauthorized("A valid payment-bound passkey assertion is required.", "PAYMENT_AUTH_REQUIRED");
  const now = Date.now();
  const token = randomToken(32);
  db.prepare("INSERT INTO payment_authorizations (token_hash, user_id, expires_at, created_at, intent_hash) VALUES (?, ?, ?, ?, ?)")
    .run(sha256Hex(token), userId, now + 120_000, now, intentHash);
  audit(userId, "payment.authorized", { method: "passkey", expiresInSeconds: 120 }, ip);
  return { authorizationToken: token, expiresIn: 120 };
}

export async function createPaymentAuthorization(
  userId: string,
  factor: { method: "password"; secret: string } | { method: "mpin"; secret: string },
  ip?: string,
  intent?: PaymentIntent
) {
  if (intent) validatePaymentIntent(intent);
  const now = Date.now();
  let valid = false;
  if (factor.method === "password") {
    const user = db.prepare("SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL")
      .get(userId) as { password_hash: string } | undefined;
    valid = Boolean(user && await verifyPassword(user.password_hash, factor.secret));
  } else {
    if (!/^\d{6}$/.test(factor.secret)) throw unauthorized("MPIN is incorrect.", "INVALID_CREDENTIALS");
    const credential = db.prepare("SELECT pin_hash, failed_attempts, locked_until FROM pin_credentials WHERE user_id = ?")
      .get(userId) as { pin_hash: string; failed_attempts: number; locked_until: number | null } | undefined;
    if (!credential) throw badRequest("Set an MPIN in More → Security before using it to approve payments.", "MPIN_NOT_SET");
    if (credential.locked_until && credential.locked_until > now) {
      throw tooManyRequests(Math.ceil((credential.locked_until - now) / 1000), "MPIN is temporarily locked after failed attempts.");
    }
    try { valid = await argon2.verify(credential.pin_hash, factor.secret, { secret: pinPepper }); }
    catch { valid = false; }
    if (valid) {
      db.prepare("UPDATE pin_credentials SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE user_id = ?").run(now, userId);
    } else {
      const attempts = credential.failed_attempts + 1;
      const lockedUntil = attempts >= 5 ? now + 15 * 60_000 : null;
      db.prepare("UPDATE pin_credentials SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE user_id = ?")
        .run(attempts, lockedUntil, now, userId);
    }
  }
  if (!valid) {
    audit(userId, "payment.authorization_failed", { method: factor.method }, ip);
    throw unauthorized("Payment authorization failed. Check your password or MPIN.", "INVALID_CREDENTIALS");
  }
  const token = randomToken(32);
  db.prepare("INSERT INTO payment_authorizations (token_hash, user_id, expires_at, created_at, intent_hash) VALUES (?, ?, ?, ?, ?)")
    .run(sha256Hex(token), userId, now + 120_000, now, intent ? paymentIntentHash(intent) : null);
  audit(userId, "payment.authorized", { method: factor.method, expiresInSeconds: 120 }, ip);
  return { authorizationToken: token, expiresIn: 120 };
}

/** One-shot authorization is stored as a hash and consumed atomically before sending. */
export function consumePaymentAuthorization(userId: string, token: string, ip?: string, intent?: PaymentIntent): void {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw unauthorized("A fresh payment authorization is required.", "PAYMENT_AUTH_REQUIRED");
  const now = Date.now();
  const expectedIntentHash = intent ? paymentIntentHash(intent) : null;
  const consumed = withTransaction(() => db.prepare(`UPDATE payment_authorizations SET used_at = ?
    WHERE token_hash = ? AND user_id = ? AND used_at IS NULL AND expires_at > ? AND intent_hash IS ?`)
    .run(now, sha256Hex(token), userId, now, expectedIntentHash).changes);
  if (consumed !== 1) throw unauthorized("Payment authorization is expired, already used, or does not match this payment. Authorize again.", "PAYMENT_AUTH_REQUIRED");
  audit(userId, "payment.authorization_consumed", { paymentBound: intent !== undefined }, ip);
}
