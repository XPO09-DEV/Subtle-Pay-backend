import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { changePassword, deleteAccount, getMe, login, register, setCurrency, updateProfile } from "./auth.service.js";
import { getMpinStatus, setMpin, removeMpin, createPaymentAuthorization } from "./paymentAuth.service.js";
import { db } from "../../db.js";
import { getHome } from "./home.js";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { revokeSession, rotateSession, TokenReuseError } from "../../lib/tokens.js";
import { audit } from "../../lib/audit.js";
import { unauthorized } from "../../lib/errors.js";
import { config } from "../../config.js";

const passwordSchema = z.string().min(1).max(128);
const registerBody = z.object({ password: passwordSchema });
const loginBody = z.object({ accountId: z.string().min(10).max(40), password: passwordSchema });
const changeBody = z.object({ oldPassword: passwordSchema, newPassword: passwordSchema });
const currencyBody = z.object({ currency: z.string().length(3) });
const profileBody = z.object({
  displayName: z.union([z.string().trim().max(80), z.null()]).optional(),
  region: z.union([z.string().trim().min(1).max(80), z.null()]).optional(),
  shareRegion: z.boolean().optional(),
}).superRefine((value, ctx) => {
  if (value.shareRegion === true && !value.region?.trim()) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["region"], message: "Choose a region to share" });
  if (value.region !== undefined && value.shareRegion === undefined) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["shareRegion"], message: "Explicit region-sharing consent is required" });
});
const refreshBody = z.object({ refreshToken: z.string().min(20).max(128).optional() }).default({});
const REFRESH_COOKIE = "subtlepay_refresh";
function cookieValue(req: { headers: { cookie?: string } }, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const segment of header.split(";")) {
    const index = segment.indexOf("=");
    if (index < 0) continue;
    if (segment.slice(0, index).trim() === name) {
      try { return decodeURIComponent(segment.slice(index + 1).trim()); } catch { return null; }
    }
  }
  return null;
}
function refreshCookie(value: string, clear = false): string {
  const production = config.NODE_ENV === "production";
  return [
    `${REFRESH_COOKIE}=${clear ? "" : encodeURIComponent(value)}`, "Path=/auth", "HttpOnly",
    `SameSite=${production ? "None" : "Lax"}`, ...(production ? ["Secure"] : []),
    "Priority=High", `Max-Age=${clear ? 0 : config.REFRESH_TOKEN_TTL_DAYS * 86400}`,
  ].join("; ");
}
function meta(req: { id: string; ip: string; headers: { "user-agent"?: string | string[] } }) {
  const ua = req.headers["user-agent"];
  return { ip: req.ip, userAgent: (Array.isArray(ua) ? ua[0] : ua)?.slice(0, 512), requestId: req.id };
}
export async function authRoutes(app: FastifyInstance): Promise<void> {
  app.post("/auth/register", { config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req, reply) => {
    const body = registerBody.parse(req.body);
    const result = await register(body.password, meta(req));
    reply.header("set-cookie", refreshCookie(result.refreshToken));
    return { accountId: result.accountId, token: result.token, expiresIn: result.expiresIn, address: result.address };
  });
  app.post("/auth/login", { config: { rateLimit: { max: 10, timeWindow: 60_000 } } }, async (req, reply) => {
    const body = loginBody.parse(req.body);
    const result = await login(body.accountId, body.password, meta(req));
    reply.header("set-cookie", refreshCookie(result.refreshToken));
    return { token: result.token, expiresIn: result.expiresIn };
  });
  app.post("/auth/refresh", async (req, reply) => {
    const body = refreshBody.parse(req.body ?? {});
    const refreshToken = cookieValue(req, REFRESH_COOKIE) ?? body.refreshToken;
    if (!refreshToken) throw unauthorized("Refresh session is missing or expired");
    try {
      const next = await rotateSession(refreshToken, meta(req));
      reply.header("set-cookie", refreshCookie(next.refreshToken));
      return { token: next.accessToken, expiresIn: next.accessTokenExpiresIn };
    } catch (err) {
      if (err instanceof TokenReuseError) audit(err.userId, "auth.token_reused", undefined, req.ip);
      reply.header("set-cookie", refreshCookie("", true));
      throw err;
    }
  });
  app.post("/auth/logout", { preHandler: requireAuth }, async (req, reply) => {
    const user = currentUser(req);
    revokeSession(user.sessionId); audit(user.id, "auth.logout", undefined, req.ip);
    reply.header("set-cookie", refreshCookie("", true));
    return { ok: true };
  });
  app.post("/auth/change-password", { preHandler: requireAuth }, async (req) => {
    const user = currentUser(req); const body = changeBody.parse(req.body);
    return changePassword(user.id, user.sessionId, body.oldPassword, body.newPassword, req.ip);
  });
  app.get("/me", { preHandler: requireAuth }, async (req) => getMe(currentUser(req).id));

  app.get("/me/sessions", { preHandler: requireAuth }, async (req) => {
    const user = currentUser(req);
    const now = Date.now();
    const rows = db.prepare(`SELECT family_id AS sessionId, MIN(created_at) AS createdAt,
      MAX(created_at) AS lastSeenAt, MAX(expires_at) AS expiresAt, MAX(ip) AS ip,
      MAX(user_agent) AS userAgent
      FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
      GROUP BY family_id ORDER BY MAX(created_at) DESC LIMIT 50`).all(user.id, now) as Array<Record<string, unknown> & { sessionId: string }>;
    return { sessions: rows.map((row) => ({ ...row, current: row.sessionId === user.sessionId })), updatedAt: new Date().toISOString() };
  });
  app.delete("/me/sessions/:sessionId", { preHandler: requireAuth }, async (req) => {
    const user = currentUser(req);
    const sessionId = (req.params as { sessionId: string }).sessionId;
    if (!/^[0-9a-f-]{20,64}$/i.test(sessionId)) throw unauthorized("Invalid session identifier");
    if (sessionId === user.sessionId) throw badRequest("Use Sign out to end the current session.", "CURRENT_SESSION");
    const row = db.prepare("SELECT 1 FROM refresh_tokens WHERE user_id = ? AND family_id = ?").get(user.id, sessionId);
    if (!row) throw unauthorized("Session not found");
    revokeSession(sessionId);
    audit(user.id, "auth.session_revoked", { sessionId }, req.ip);
    return { ok: true };
  });

  app.get("/auth/mpin/status", { preHandler: requireAuth }, async (req) => getMpinStatus(currentUser(req).id));
  app.put("/auth/mpin", { preHandler: requireAuth, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req) => {
    const body = z.object({ currentPassword: passwordSchema, pin: z.string().regex(/^\\d{6}$/) }).parse(req.body);
    return setMpin(currentUser(req).id, body.currentPassword, body.pin, req.ip);
  });
  app.delete("/auth/mpin", { preHandler: requireAuth, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req) => {
    const body = z.object({ currentPassword: passwordSchema }).parse(req.body);
    return removeMpin(currentUser(req).id, body.currentPassword, req.ip);
  });
  app.post("/auth/payment-authorization", { preHandler: requireAuth, config: { rateLimit: { max: 8, timeWindow: 60_000 } } }, async (req) => {
    const body = z.discriminatedUnion("method", [
      z.object({ method: z.literal("password"), secret: passwordSchema }),
      z.object({ method: z.literal("mpin"), secret: z.string().regex(/^\\d{6}$/) }),
    ]).parse(req.body);
    return createPaymentAuthorization(currentUser(req).id, body, req.ip);
  });
  app.post("/me/delete", { preHandler: requireAuth, config: { rateLimit: { max: 3, timeWindow: 60_000 } } }, async (req, reply) => {
    const body = z.object({ currentPassword: passwordSchema, confirmation: z.literal("DELETE") }).parse(req.body);
    const user = currentUser(req);
    const result = await deleteAccount(user.id, body.currentPassword, req.ip);
    reply.header("set-cookie", refreshCookie("", true));
    return result;
  });
  app.get("/home", { preHandler: requireAuth }, async (req) => {
    const query = z.object({ refresh: z.enum(["true", "false"]).optional() }).parse(req.query);
    return getHome(currentUser(req).id, query.refresh === "true");
  });
  app.put("/me/currency", { preHandler: requireAuth }, async (req) => {
    const body = currencyBody.parse(req.body);
    return setCurrency(currentUser(req).id, body.currency);
  });
  app.put("/me/profile", { preHandler: requireAuth }, async (req) => {
    const body = profileBody.parse(req.body);
    const user = currentUser(req);
    const profile = updateProfile(user.id, body);
    audit(user.id, "profile.updated", {
      displayNameChanged: body.displayName !== undefined,
      regionSharing: body.shareRegion === true ? "enabled" : body.shareRegion === false ? "disabled" : "unchanged",
    }, req.ip);
    return profile;
  });
}
