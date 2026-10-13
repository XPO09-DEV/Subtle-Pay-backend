import { SignJWT, jwtVerify, errors as joseErrors } from "jose";
import { config } from "../config.js";
import { db, withTransaction, type RefreshTokenRow } from "../db.js";
import { newId, randomToken, sha256Hex } from "./crypto.js";
import { AppError, unauthorized } from "./errors.js";

const ISSUER = "subtle-pay";
const AUDIENCE = "subtle-pay-api";
const ACCESS_KEY = Buffer.from(config.JWT_ACCESS_SECRET, "hex");
const DAY_MS = 86_400_000;
const REFRESH_TTL_MS = config.REFRESH_TOKEN_TTL_DAYS * DAY_MS;
const SESSION_MAX_MS = 90 * DAY_MS;
const REUSE_GRACE_MS = 10_000;
const REFRESH_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const ACCESS_TOKEN_TTL_SECONDS = config.ACCESS_TOKEN_TTL_SECONDS;

export interface SessionMeta { ip?: string; userAgent?: string; requestId?: string; }
export interface IssuedSession {
  sessionId: string;
  accessToken: string;
  accessTokenExpiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: number;
}
export interface AccessClaims { userId: string; sessionId: string; expiresAt: number; }
export class TokenReuseError extends AppError {
  constructor(public readonly userId: string, public readonly sessionId: string) {
    super(401, "TOKEN_REUSED", "Session is no longer valid. Please log in again.");
    this.name = "TokenReuseError";
  }
}

async function signAccessToken(userId: string, sessionId: string): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" }).setSubject(userId).setIssuer(ISSUER)
    .setAudience(AUDIENCE).setJti(newId()).setIssuedAt(nowSec)
    .setExpirationTime(nowSec + ACCESS_TOKEN_TTL_SECONDS).sign(ACCESS_KEY);
}
export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  let payload;
  try {
    ({ payload } = await jwtVerify(token, ACCESS_KEY, { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE, clockTolerance: 5 }));
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) throw unauthorized("Session expired", "TOKEN_EXPIRED");
    throw unauthorized("Invalid or missing token");
  }
  const userId = payload.sub;
  const sessionId = payload.sid;
  if (typeof userId !== "string" || typeof sessionId !== "string" || !payload.exp) throw unauthorized("Invalid or missing token");
  if (!isSessionActive(sessionId)) throw unauthorized("Session has ended. Please log in again.");
  return { userId, sessionId, expiresAt: payload.exp * 1000 };
}
export function parseBearer(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer ([A-Za-z0-9._-]{20,4096})$/.exec(header.trim());
  return match?.[1];
}
const clip = (value: string | undefined, max: number): string | null => value ? value.slice(0, max) : null;

function insertRefreshToken(userId: string, sessionId: string, meta: SessionMeta, now: number): { id: string; raw: string; expiresAt: number } {
  const id = newId();
  const raw = randomToken(32);
  const expiresAt = now + REFRESH_TTL_MS;
  db.prepare(`INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(id, userId, sessionId, sha256Hex(raw), expiresAt, clip(meta.ip, 64), clip(meta.userAgent, 256), now);
  return { id, raw, expiresAt };
}
export async function issueSession(userId: string, meta: SessionMeta = {}): Promise<IssuedSession> {
  const sessionId = newId();
  const accessToken = await signAccessToken(userId, sessionId);
  const refresh = insertRefreshToken(userId, sessionId, meta, Date.now());
  return { sessionId, accessToken, accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS, refreshToken: refresh.raw, refreshTokenExpiresAt: refresh.expiresAt };
}
type RotateOutcome =
  | { kind: "ok"; userId: string; sessionId: string; refresh: { raw: string; expiresAt: number } }
  | { kind: "invalid" } | { kind: "expired" } | { kind: "raced" }
  | { kind: "reused"; userId: string; sessionId: string };

function revokeFamily(sessionId: string, now: number): void {
  db.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL").run(now, sessionId);
}
/** Exchange a single-use refresh token; decide transaction outcome before throwing to retain theft revocation. */
export async function rotateSession(refreshToken: string, meta: SessionMeta = {}): Promise<IssuedSession & { userId: string }> {
  if (typeof refreshToken !== "string" || !REFRESH_TOKEN_RE.test(refreshToken)) throw unauthorized("Invalid refresh token");
  const hash = sha256Hex(refreshToken);
  const now = Date.now();
  const outcome = withTransaction((): RotateOutcome => {
    const row = db.prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?").get(hash) as RefreshTokenRow | undefined;
    if (!row || row.revoked_at !== null) return { kind: "invalid" };
    if (row.used_at !== null) {
      if (now - row.used_at <= REUSE_GRACE_MS) return { kind: "raced" };
      revokeFamily(row.family_id, now);
      return { kind: "reused", userId: row.user_id, sessionId: row.family_id };
    }
    if (row.expires_at <= now) return { kind: "expired" };
    const first = db.prepare("SELECT MIN(created_at) AS t FROM refresh_tokens WHERE family_id = ?").get(row.family_id) as { t: number };
    if (now - first.t > SESSION_MAX_MS) {
      revokeFamily(row.family_id, now);
      return { kind: "expired" };
    }
    const next = insertRefreshToken(row.user_id, row.family_id, meta, now);
    db.prepare("UPDATE refresh_tokens SET used_at = ?, replaced_by = ? WHERE id = ?").run(now, next.id, row.id);
    return { kind: "ok", userId: row.user_id, sessionId: row.family_id, refresh: { raw: next.raw, expiresAt: next.expiresAt } };
  });
  switch (outcome.kind) {
    case "ok": {
      const accessToken = await signAccessToken(outcome.userId, outcome.sessionId);
      return { userId: outcome.userId, sessionId: outcome.sessionId, accessToken, accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS, refreshToken: outcome.refresh.raw, refreshTokenExpiresAt: outcome.refresh.expiresAt };
    }
    case "reused": throw new TokenReuseError(outcome.userId, outcome.sessionId);
    case "expired": throw unauthorized("Session expired. Please log in again.", "TOKEN_EXPIRED");
    case "raced": throw unauthorized("Refresh token was just used");
    default: throw unauthorized("Invalid refresh token");
  }
}
export function isSessionActive(sessionId: string, now = Date.now()): boolean {
  return db.prepare(`SELECT 1 FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NULL AND expires_at > ? LIMIT 1`).get(sessionId, now) !== undefined;
}
export function revokeSession(sessionId: string): void { revokeFamily(sessionId, Date.now()); }
export function revokeSessionByRefreshToken(refreshToken: string): string | null {
  if (typeof refreshToken !== "string" || !REFRESH_TOKEN_RE.test(refreshToken)) return null;
  const row = db.prepare("SELECT family_id FROM refresh_tokens WHERE token_hash = ?").get(sha256Hex(refreshToken)) as { family_id: string } | undefined;
  if (!row) return null;
  revokeFamily(row.family_id, Date.now());
  return row.family_id;
}
export function revokeAllSessions(userId: string, exceptSessionId?: string): void {
  db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND family_id IS NOT ?`).run(Date.now(), userId, exceptSessionId ?? null);
}
export function purgeExpiredTokens(now = Date.now()): number {
  return db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ?").run(now - 7 * DAY_MS).changes;
}
