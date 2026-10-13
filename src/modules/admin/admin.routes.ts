import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { config } from "../../config.js";
import { db } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { getWalletView } from "../wallet/wallet.service.js";

const datasetSchema = z.enum(["users", "payments", "sessions", "audit", "logins"]);
const pageSchema = z.object({ limit: z.coerce.number().int().min(1).max(10).default(10), offset: z.coerce.number().int().min(0).max(50_000).default(0) });
const transactionPageSchema = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50), offset: z.coerce.number().int().min(0).max(50_000).default(0), status: z.enum(["pending", "submitted", "confirmed", "failed"]).optional() });
const EXPORT_ROW_LIMIT = 50_000;
function matchesAdminToken(value: string | undefined): boolean {
  const expected = config.ADMIN_API_TOKEN;
  if (!expected || !value) return false;
  const actual = Buffer.from(value, "utf8"), wanted = Buffer.from(expected, "utf8");
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}
async function requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!config.ADMIN_API_TOKEN) {
    await reply.code(503).send({ error: { code: "ADMIN_DISABLED", message: "Admin API is disabled until ADMIN_API_TOKEN is configured on the server." } });
    return;
  }
  const raw = req.headers["x-admin-token"];
  if (!matchesAdminToken(typeof raw === "string" ? raw : undefined)) {
    await reply.code(401).send({ error: { code: "UNAUTHORIZED", message: "Admin authorization required." } });
  }
}
function timeSql(column: string): string {
  return "CASE WHEN " + column + " IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%fZ', " + column + " / 1000.0, 'unixepoch') END";
}
function rowsFor(dataset: z.infer<typeof datasetSchema>): Record<string, unknown>[] {
  if (dataset === "users") return db.prepare(`
    SELECT u.id AS account_id, COALESCE(u.display_name, a.alias, '') AS display_name,
      a.alias AS handle, w.address AS wallet_address, u.currency AS preferred_currency,
      ${timeSql("u.created_at")} AS account_created_at, ${timeSql("w.created_at")} AS wallet_created_at,
      ${timeSql("(SELECT MAX(created_at) FROM login_events WHERE user_id = u.id AND outcome = 'success')")} AS last_login_at,
      (SELECT ip FROM refresh_tokens r WHERE r.user_id = u.id ORDER BY r.created_at DESC LIMIT 1) AS recent_session_ip,
      (SELECT user_agent FROM refresh_tokens r WHERE r.user_id = u.id ORDER BY r.created_at DESC LIMIT 1) AS recent_user_agent,
      CASE WHEN u.region_consent_at IS NOT NULL THEN u.region ELSE NULL END AS consented_region,
      ${timeSql("u.region_consent_at")} AS region_consent_at
    FROM users u LEFT JOIN aliases a ON a.user_id=u.id LEFT JOIN wallets w ON w.user_id=u.id
    ORDER BY u.created_at DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
  if (dataset === "payments") return db.prepare(`
    SELECT t.id AS payment_id, t.from_user AS sender_account_id, COALESCE(fa.alias,'') AS sender_handle,
      t.from_address AS sender_wallet, t.to_user AS recipient_account_id, COALESCE(ta.alias,'') AS recipient_handle,
      t.to_address AS recipient_wallet, CAST(t.amount_micro AS REAL)/1000000.0 AS amount_usd,
      t.display_currency AS entered_currency, t.fx_rate AS usd_to_display_currency_rate, t.status,
      t.tx_hash AS transaction_hash, t.failure_reason, t.note,
      ${timeSql("t.created_at")} AS created_at, ${timeSql("t.confirmed_at")} AS confirmed_at,
      ${timeSql("t.updated_at")} AS updated_at
    FROM transactions t LEFT JOIN aliases fa ON fa.user_id=t.from_user LEFT JOIN aliases ta ON ta.user_id=t.to_user
    ORDER BY t.created_at DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
  if (dataset === "logins") return db.prepare(`
    SELECT id AS event_id, user_id AS account_id, account_id_hash, outcome, reason,
      ip AS ip_address, user_agent, ${timeSql("created_at")} AS timestamp
    FROM login_events ORDER BY created_at DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
  if (dataset === "sessions") return db.prepare(`
    SELECT r.id AS session_record_id, r.user_id AS account_id, r.family_id AS session_family_id,
      ${timeSql("r.created_at")} AS created_at, ${timeSql("r.expires_at")} AS expires_at,
      ${timeSql("r.used_at")} AS token_used_at, ${timeSql("r.revoked_at")} AS revoked_at,
      r.ip AS ip_address, r.user_agent
    FROM refresh_tokens r ORDER BY r.created_at DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
  return db.prepare(`
    SELECT seq AS audit_sequence, ${timeSql("ts")} AS timestamp, actor, action, details,
      ip AS ip_address, prev_hash, hash FROM audit_log ORDER BY seq DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
}
function safeCell(value: unknown): string {
  let cell = value == null ? "" : String(value);
  if (["=", "+", "-", "@", "\t", "\r"].includes(cell.charAt(0))) cell = "'" + cell;
  return "\"" + cell.replace(/"/g, '""') + "\"";
}
function toCsv(rows: Record<string, unknown>[]): string {
  if (!rows.length) return "\uFEFFNo records\r\n";
  const columns = Object.keys(rows[0]);
  return "\uFEFF" + [columns.map(safeCell).join(","), ...rows.map((row) => columns.map((col) => safeCell(row[col])).join(","))].join("\r\n") + "\r\n";
}
export async function adminRoutes(app: FastifyInstance): Promise<void> {
  app.get("/admin/overview", { preHandler: requireAdmin, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    audit("admin", "admin.overview", undefined, req.ip);
    const counts = db.prepare(`
      SELECT (SELECT COUNT(*) FROM users) AS accounts, (SELECT COUNT(*) FROM wallets) AS wallets,
      (SELECT COUNT(*) FROM transactions) AS payments,
      (SELECT COUNT(*) FROM transactions WHERE status='confirmed') AS confirmedPayments,
      (SELECT COUNT(*) FROM transactions WHERE status IN ('pending','submitted')) AS unsettledPayments,
      (SELECT COUNT(*) FROM login_events WHERE outcome='success' AND created_at >= ?) AS loginsLast24Hours,
      (SELECT COUNT(*) FROM login_events WHERE outcome='failure' AND created_at >= ?) AS failedLoginsLast24Hours,
      (SELECT COUNT(*) FROM fund_holds WHERE status='active') AS activeFundHolds,
      (SELECT COUNT(*) FROM users WHERE region_consent_at IS NOT NULL) AS consentedRegions
    `).get(Date.now() - 86_400_000, Date.now() - 86_400_000);
    return { ...(counts as Record<string, number>), exportDatasets: ["users","payments","sessions","audit","logins"], updatedAt: new Date().toISOString() };
  });
  app.get("/admin/users", { preHandler: requireAdmin, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const query = pageSchema.parse(req.query);
    const rows = db.prepare(`
      SELECT u.id AS accountId, COALESCE(u.display_name, a.alias, '') AS displayName,
        a.alias AS alias, w.address AS walletAddress, u.currency AS preferredCurrency,
        u.created_at AS accountCreatedAt,
        (SELECT MAX(created_at) FROM login_events le WHERE le.user_id = u.id AND le.outcome = 'success') AS lastLoginAt,
        (SELECT COUNT(*) FROM transactions t WHERE t.from_user = u.id OR t.to_user = u.id) AS transactionCount,
        (SELECT MAX(created_at) FROM transactions t WHERE t.from_user = u.id OR t.to_user = u.id) AS lastTransactionAt
      FROM users u
      LEFT JOIN aliases a ON a.user_id = u.id
      LEFT JOIN wallets w ON w.user_id = u.id
      ORDER BY u.created_at DESC, u.id DESC
      LIMIT ? OFFSET ?
    `).all(query.limit + 1, query.offset) as Array<Record<string, unknown>>;
    const hasMore = rows.length > query.limit;
    const page = rows.slice(0, query.limit);
    const items = await Promise.all(page.map(async (row) => {
      const accountId = String(row.accountId);
      try {
        const wallet = await getWalletView(accountId);
        return {
          ...row,
          balance: {
            asset: wallet.asset,
            chainId: wallet.chainId,
            availableToken: wallet.balanceToken,
            availableUsd: wallet.balanceUsd,
            reservedToken: wallet.reservedToken,
            onChainToken: wallet.onChainBalanceToken,
            updatedAt: wallet.balanceUpdatedAt,
          },
        };
      } catch {
        return { ...row, balance: null, balanceUnavailable: true };
      }
    }));
    audit("admin", "admin.users", { limit: query.limit, offset: query.offset }, req.ip);
    return { items, nextOffset: hasMore ? query.offset + query.limit : null, updatedAt: new Date().toISOString() };
  });

  app.get("/admin/transactions", { preHandler: requireAdmin, config: { rateLimit: { max: 10, timeWindow: 60_000 } } }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const query = transactionPageSchema.parse(req.query);
    const rows = query.status
      ? db.prepare(`
          SELECT t.id AS transactionId, t.from_user AS senderAccountId,
            COALESCE(fa.alias, '') AS senderAlias, t.from_address AS senderWallet,
            t.to_user AS recipientAccountId, COALESCE(ta.alias, '') AS recipientAlias,
            t.to_address AS recipientWallet, t.amount_micro AS amountMicro,
            t.display_currency AS displayCurrency, t.fx_rate AS fxRate, t.status,
            t.tx_hash AS txHash, t.failure_reason AS failureReason, t.note,
            t.created_at AS createdAt, t.updated_at AS updatedAt, t.confirmed_at AS confirmedAt
          FROM transactions t
          LEFT JOIN aliases fa ON fa.user_id = t.from_user
          LEFT JOIN aliases ta ON ta.user_id = t.to_user
          WHERE t.status = ?
          ORDER BY t.created_at DESC, t.id DESC LIMIT ? OFFSET ?
        `).all(query.status, query.limit, query.offset)
      : db.prepare(`
          SELECT t.id AS transactionId, t.from_user AS senderAccountId,
            COALESCE(fa.alias, '') AS senderAlias, t.from_address AS senderWallet,
            t.to_user AS recipientAccountId, COALESCE(ta.alias, '') AS recipientAlias,
            t.to_address AS recipientWallet, t.amount_micro AS amountMicro,
            t.display_currency AS displayCurrency, t.fx_rate AS fxRate, t.status,
            t.tx_hash AS txHash, t.failure_reason AS failureReason, t.note,
            t.created_at AS createdAt, t.updated_at AS updatedAt, t.confirmed_at AS confirmedAt
          FROM transactions t
          LEFT JOIN aliases fa ON fa.user_id = t.from_user
          LEFT JOIN aliases ta ON ta.user_id = t.to_user
          ORDER BY t.created_at DESC, t.id DESC LIMIT ? OFFSET ?
        `).all(query.limit, query.offset);
    audit("admin", "admin.transactions", { limit: query.limit, offset: query.offset, status: query.status ?? "all" }, req.ip);
    return { items: rows, limit: query.limit, offset: query.offset, nextOffset: rows.length === query.limit ? query.offset + query.limit : null, updatedAt: new Date().toISOString() };
  });

  app.get("/admin/export.csv", { preHandler: requireAdmin, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req, reply) => {
    const query = z.object({ dataset: datasetSchema.default("users") }).parse(req.query);
    audit("admin", "admin.export", { dataset: query.dataset }, req.ip);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    return reply.type("text/csv; charset=utf-8")
      .header("content-disposition", `attachment; filename="subtle-pay-${query.dataset}-${stamp}.csv"`)
      .header("cache-control", "no-store, private")
      .send(toCsv(rowsFor(query.dataset)));
  });
}
