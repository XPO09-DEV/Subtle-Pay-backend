import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { currentUser, requireAuth } from "../../middleware/auth.js";

const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
  unreadOnly: z.enum(["true", "false"]).default("false"),
});
const notificationParams = z.object({ id: z.string().min(1).max(160) });

export async function notificationRoutes(app: FastifyInstance): Promise<void> {
  app.get("/notifications", { preHandler: requireAuth }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const query = listQuery.parse(req.query);
    const userId = currentUser(req).id;
    const filter = query.unreadOnly === "true" ? " AND read_at IS NULL" : "";
    const count = db.prepare(`SELECT COUNT(*) AS total FROM notifications WHERE user_id = ?${filter}`)
      .get(userId) as { total: number };
    const unread = db.prepare("SELECT COUNT(*) AS total FROM notifications WHERE user_id = ? AND read_at IS NULL")
      .get(userId) as { total: number };
    const rows = db.prepare(`
      SELECT id, transaction_id AS transactionId, type, title, message, created_at AS createdAt, read_at AS readAt
      FROM notifications WHERE user_id = ?${filter}
      ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?
    `).all(userId, query.limit + 1, query.offset) as Array<{
      id: string; transactionId: string; type: string; title: string; message: string; createdAt: number; readAt: number | null;
    }>;
    const hasMore = rows.length > query.limit;
    const items = rows.slice(0, query.limit).map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt).toISOString(),
      readAt: row.readAt === null ? null : new Date(row.readAt).toISOString(),
    }));
    return { items, total: count.total, unreadCount: unread.total, limit: query.limit, offset: query.offset, nextOffset: hasMore ? query.offset + query.limit : null, updatedAt: new Date().toISOString() };
  });

  app.post("/notifications/:id/read", { preHandler: requireAuth }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const { id } = notificationParams.parse(req.params);
    const userId = currentUser(req).id;
    const readAt = Date.now();
    const result = db.prepare("UPDATE notifications SET read_at = COALESCE(read_at, ?) WHERE id = ? AND user_id = ?").run(readAt, id, userId);
    if (result.changes !== 1) return reply.code(404).send({ error: { code: "NOT_FOUND", message: "Notification not found", requestId: req.id } });
    audit(userId, "notification.read", { notificationId: id }, req.ip);
    return { ok: true, readAt: new Date(readAt).toISOString() };
  });

  app.post("/notifications/read-all", { preHandler: requireAuth }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const userId = currentUser(req).id;
    const readAt = Date.now();
    const result = db.prepare("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL").run(readAt, userId);
    audit(userId, "notification.read_all", { count: result.changes }, req.ip);
    return { ok: true, updated: result.changes, readAt: new Date(readAt).toISOString() };
  });
}