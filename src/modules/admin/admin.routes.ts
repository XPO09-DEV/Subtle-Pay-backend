import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { config } from "../../config.js";
import { db } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { conflict, notFound, serviceUnavailable, unauthorized } from "../../lib/errors.js";
import { formatEther, type Address } from "viem";
import { getNativeBalance } from "../../chain/monad.js";

const datasetSchema = z.enum(["users", "payments", "sessions", "audit"]);
const EXPORT_ROW_LIMIT = 50_000;
function matchesAdminToken(value: string | undefined): boolean {
  const expected = config.ADMIN_API_TOKEN;
  if (!expected || !value) return false;
  const actual = Buffer.from(value, "utf8"), wanted = Buffer.from(expected, "utf8");
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}
async function requireAdmin(_req: FastifyRequest, _reply: FastifyReply): Promise<void> {
  // Throwing aborts the request lifecycle before any admin handler runs.
  // The token is server-only and compared in constant time.
  if (!config.ADMIN_API_TOKEN) {
    throw serviceUnavailable("Admin API is disabled until ADMIN_API_TOKEN is configured on the server.", "FORBIDDEN");
  }
  const raw = _req.headers["x-admin-token"];
  if (!matchesAdminToken(typeof raw === "string" ? raw : undefined)) {
    throw unauthorized("Admin authorization required.");
  }
}
function timeSql(column: string): string {
  return "CASE WHEN " + column + " IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%fZ', " + column + " / 1000.0, 'unixepoch') END";
}
function rowsFor(dataset: z.infer<typeof datasetSchema>): Record<string, unknown>[] {
  if (dataset === "users") return db.prepare(`
    SELECT u.id AS account_id, COALESCE(u.display_name, a.alias, '') AS display_name,
      a.alias AS handle, w.address AS wallet_address, u.currency AS preferred_currency,
      ${timeSql("u.deleted_at")} AS account_deleted_at,
      ${timeSql("u.created_at")} AS account_created_at, ${timeSql("w.created_at")} AS wallet_created_at,
      ${timeSql("COALESCE((SELECT MAX(event_at) FROM login_events WHERE account_id = u.id AND success = 1 AND reason = 'success'), (SELECT MAX(ts) FROM audit_log WHERE actor = u.id AND action = 'auth.login'))")} AS last_login_at,
      (SELECT COUNT(*) FROM transactions t WHERE t.from_user=u.id OR t.to_user=u.id) AS transaction_count,
      (SELECT COUNT(*) FROM transactions t WHERE (t.from_user=u.id OR t.to_user=u.id) AND t.status='confirmed') AS confirmed_transaction_count,
      (SELECT COUNT(*) FROM fund_holds fh WHERE fh.user_id=u.id AND fh.status='active') AS active_fund_holds
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
  if (dataset === "sessions") return db.prepare(`
    SELECT le.account_id, COALESCE(u.display_name, a.alias, '') AS display_name, a.alias, le.success, le.reason,
      le.ip, le.user_agent, le.request_id, ${timeSql("le.event_at")} AS event_at
    FROM login_events le LEFT JOIN users u ON u.id=le.account_id LEFT JOIN aliases a ON a.user_id=le.account_id
    ORDER BY le.event_at DESC LIMIT ${EXPORT_ROW_LIMIT}
  `).all() as Record<string, unknown>[];
  return db.prepare(`
    SELECT seq AS audit_sequence, ${timeSql("ts")} AS timestamp, actor, action, prev_hash, hash
    FROM audit_log ORDER BY seq DESC LIMIT ${EXPORT_ROW_LIMIT}
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
  app.get("/admin/users", { preHandler: requireAdmin, config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({ limit: z.coerce.number().int().min(1).max(50).default(25), before: z.string().max(27).optional() }).parse(req.query);
    const where = query.before ? "WHERE u.id < ?" : "";
    const args = query.before ? [query.before, query.limit] : [query.limit];
    const rows = db.prepare(`SELECT u.id AS accountId,
      COALESCE(u.display_name, a.alias, '') AS displayName, a.alias, w.address AS walletAddress, u.currency,
      COALESCE((SELECT MAX(le.event_at) FROM login_events le WHERE le.account_id = u.id AND le.success = 1 AND le.reason = 'success'),
        (SELECT MAX(al.ts) FROM audit_log al WHERE al.actor = u.id AND al.action = 'auth.login')) AS lastLoginAt,
      (SELECT COUNT(*) FROM transactions t WHERE t.from_user = u.id OR t.to_user = u.id) AS transactionCount,
      (SELECT COUNT(*) FROM transactions t WHERE (t.from_user = u.id OR t.to_user = u.id) AND t.status = 'confirmed') AS confirmedTransactionCount,
      (SELECT COUNT(*) FROM fund_holds fh WHERE fh.user_id = u.id AND fh.status = 'active') AS activeFundHolds
      FROM users u LEFT JOIN aliases a ON a.user_id = u.id LEFT JOIN wallets w ON w.user_id = u.id
      ${where} ORDER BY u.id DESC LIMIT ?`).all(...args) as Array<Record<string, unknown>>;
    for (let i = 0; i < rows.length; i += 5) {
      await Promise.all(rows.slice(i, i + 5).map(async (row) => {
        const accountId = String(row.accountId);
        const address = typeof row.walletAddress === "string" ? row.walletAddress as Address : null;
        let onChainWei: bigint | null = null;
        try { if (address) onChainWei = await getNativeBalance(address); } catch { /* balance is explicitly unavailable */ }
        const holds = db.prepare("SELECT amount_atomic FROM fund_holds WHERE user_id = ? AND asset = 'MON' AND status = 'active'").all(accountId) as Array<{ amount_atomic: string }>;
        const reservedWei = holds.reduce((total, item) => total + BigInt(item.amount_atomic), 0n);
        const availableWei = onChainWei === null ? null : onChainWei > reservedWei ? onChainWei - reservedWei : 0n;
        const recentTransactions = db.prepare(`SELECT id, CASE WHEN from_user = ? THEN 'out' ELSE 'in' END AS direction,
          CASE WHEN from_user = ? THEN to_address ELSE from_address END AS counterparty,
          amount_micro AS amountMicro, display_currency AS displayCurrency, status, tx_hash AS txHash,
          created_at AS createdAt, updated_at AS updatedAt, confirmed_at AS confirmedAt
          FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY created_at DESC, id DESC LIMIT 5`)
          .all(accountId, accountId, accountId, accountId) as Array<Record<string, unknown>>;
        row.onChainBalances = { MON: onChainWei === null ? null : formatEther(onChainWei) };
        row.reservedBalances = { MON: formatEther(reservedWei) };
        row.availableBalances = { MON: availableWei === null ? null : formatEther(availableWei) };
        row.recentTransactions = recentTransactions;
      }));
    }
    const last = rows.at(-1);
    audit("admin", "admin.users.list", { count: rows.length, limit: query.limit }, req.ip);
    return { users: rows, nextCursor: rows.length === query.limit && last ? last.accountId : null, updatedAt: new Date().toISOString() };
  });
  app.get("/admin/transactions", { preHandler: requireAdmin, config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50), before: z.coerce.number().int().positive().optional() }).parse(req.query);
    const rows = db.prepare(`SELECT t.id, COALESCE(ua.display_name, aa.alias, '') AS senderName, aa.alias AS senderAlias,
      t.from_address AS senderAddress, COALESCE(ub.display_name, ab.alias, '') AS recipientName, ab.alias AS recipientAlias,
      t.to_address AS recipientAddress, t.amount_micro AS amountMicro, t.display_currency AS displayCurrency,
      t.status, t.tx_hash AS txHash, t.failure_reason AS failureReason, t.created_at AS createdAt, t.updated_at AS updatedAt, t.confirmed_at AS confirmedAt
      FROM transactions t LEFT JOIN users ua ON ua.id=t.from_user LEFT JOIN aliases aa ON aa.user_id=t.from_user
      LEFT JOIN users ub ON ub.id=t.to_user LEFT JOIN aliases ab ON ab.user_id=t.to_user
      WHERE (? IS NULL OR t.created_at < ?) ORDER BY t.created_at DESC, t.id DESC LIMIT ?`)
      .all(query.before ?? null, query.before ?? null, query.limit) as Array<Record<string, unknown>>;
    const last = rows.at(-1);
    audit("admin", "admin.transactions.list", { count: rows.length, limit: query.limit }, req.ip);
    return { transactions: rows, nextCursor: rows.length === query.limit && last ? last.createdAt : null, updatedAt: new Date().toISOString() };
  });
  app.get("/admin/overview", { preHandler: requireAdmin, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    audit("admin", "admin.overview", undefined, req.ip);
    const counts = db.prepare(`SELECT (SELECT COUNT(*) FROM users) AS accounts, (SELECT COUNT(*) FROM wallets) AS wallets,
      (SELECT COUNT(*) FROM transactions) AS payments, (SELECT COUNT(*) FROM transactions WHERE status='confirmed') AS confirmedPayments,
      (SELECT COUNT(*) FROM transactions WHERE status IN ('pending','submitted')) AS unsettledPayments,
      (SELECT COUNT(*) FROM login_events WHERE success=1 AND reason='success' AND event_at >= ?) AS loginsLast24Hours,
      (SELECT COUNT(*) FROM users WHERE region_consent_at IS NOT NULL) AS consentedRegions`).get(Date.now() - 86_400_000);
    return { ...(counts as Record<string, number>), exportDatasets: ["users", "payments", "sessions", "audit"], updatedAt: new Date().toISOString() };
  });
  app.get("/admin/export.csv", { preHandler: requireAdmin, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req, reply) => {
    const query = z.object({ dataset: datasetSchema.default("users") }).parse(req.query);
    audit("admin", "admin.export", { dataset: query.dataset }, req.ip);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    return reply.type("text/csv; charset=utf-8").header("content-disposition", `attachment; filename="subtle-pay-${query.dataset}-${stamp}.csv"`)
      .header("cache-control", "no-store, private").send(toCsv(rowsFor(query.dataset)));
  });
  app.get("/admin/merchant-applications", { preHandler: requireAdmin, config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({ status: z.enum(["pending", "approved", "rejected"]).optional(), limit: z.coerce.number().int().min(1).max(100).default(50) }).parse(req.query);
    const rows = db.prepare(`SELECT m.id, m.user_id AS userId, COALESCE(u.display_name, a.alias, '') AS displayName,
      a.alias, m.reason, m.status, m.created_at AS createdAt, m.reviewed_at AS reviewedAt, m.review_note AS reviewNote
      FROM merchant_autopay_applications m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN aliases a ON a.user_id = m.user_id
      WHERE (? IS NULL OR m.status = ?)
      ORDER BY CASE m.status WHEN 'pending' THEN 0 ELSE 1 END, m.created_at DESC LIMIT ?`)
      .all(query.status ?? null, query.status ?? null, query.limit) as Array<Record<string, unknown>>;
    audit("admin", "admin.merchant_applications.list", { count: rows.length, status: query.status ?? "all" }, req.ip);
    return { applications: rows, updatedAt: new Date().toISOString() };
  });
  app.post("/admin/merchant-applications/:id/review", { preHandler: requireAdmin, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const params = z.object({ id: z.string().min(10).max(64) }).parse(req.params);
    const body = z.object({ decision: z.enum(["approved", "rejected"]), note: z.string().trim().max(500).optional() }).parse(req.body);
    const application = db.prepare("SELECT id, user_id AS userId, status FROM merchant_autopay_applications WHERE id = ?")
      .get(params.id) as { id: string; userId: string; status: string } | undefined;
    if (!application) throw notFound("Autopay application not found");
    if (application.status !== "pending") throw conflict("This application has already been reviewed.");
    const now = Date.now();
    db.prepare("UPDATE merchant_autopay_applications SET status = ?, reviewed_at = ?, reviewed_by = 'admin', review_note = ? WHERE id = ? AND status = 'pending'")
      .run(body.decision, now, body.note ?? null, application.id);
    if (body.decision === "approved") {
      db.prepare("UPDATE merchant_profiles SET status = 'approved', verified_at = ?, updated_at = ? WHERE user_id = ?")
        .run(now, now, application.userId);
    }
    audit("admin", "admin.merchant_application.reviewed", { applicationId: application.id, decision: body.decision }, req.ip);
    return { ok: true, applicationId: application.id, status: body.decision, verifiedBadge: body.decision === "approved" };
  });
  app.get("/admin/login-events", { preHandler: requireAdmin, config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(50),
      before: z.coerce.number().int().positive().optional(),
      outcome: z.enum(["success", "failure", "all"]).default("all"),
    }).parse(req.query);
    const where = ["(? IS NULL OR le.event_at < ?)"];
    const params: Array<number | null | string> = [query.before ?? null, query.before ?? null];
    if (query.outcome === "success") where.push("le.success = 1");
    if (query.outcome === "failure") where.push("le.success = 0");
    const rows = db.prepare(`SELECT le.id, le.account_id AS accountId,
      COALESCE(u.display_name, a.alias, '') AS displayName, a.alias,
      le.success, le.reason, le.ip, le.user_agent AS userAgent, le.request_id AS requestId,
      le.event_at AS eventAt
      FROM login_events le LEFT JOIN users u ON u.id = le.account_id
      LEFT JOIN aliases a ON a.user_id = le.account_id
      WHERE ${where.join(" AND ")} ORDER BY le.event_at DESC LIMIT ?`)
      .all(...params, query.limit) as Array<Record<string, unknown>>;
    audit("admin", "admin.login_events.list", { count: rows.length, outcome: query.outcome }, req.ip);
    return { events: rows, updatedAt: new Date().toISOString() };
  });
}
