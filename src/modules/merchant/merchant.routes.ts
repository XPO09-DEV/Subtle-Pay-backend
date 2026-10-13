import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { db } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { badRequest, conflict, notFound } from "../../lib/errors.js";
import { newId } from "../../lib/crypto.js";

const enableBody = z.object({
  publicName: z.string().trim().min(1).max(80).optional(),
  category: z.string().trim().min(1).max(40).default("individual"),
});
const applicationBody = z.object({ reason: z.string().trim().min(10).max(1000) });

export async function merchantRoutes(app: FastifyInstance): Promise<void> {
  app.get("/merchant/profile", { preHandler: requireAuth }, async (req) => {
    const userId = currentUser(req).id;
    const profile = db.prepare(`SELECT user_id AS userId, public_name AS publicName, category, status,
      created_at AS createdAt, updated_at AS updatedAt, verified_at AS verifiedAt
      FROM merchant_profiles WHERE user_id = ?`).get(userId) as Record<string, unknown> | undefined;
    if (!profile) return { enabled: false, profile: null, verifiedBadge: false };
    return { enabled: true, profile, verifiedBadge: profile.status === "approved" };
  });

  app.post("/merchant/enable", { preHandler: requireAuth, config: { rateLimit: { max: 5, timeWindow: 60_000 } } }, async (req) => {
    const body = enableBody.parse(req.body ?? {});
    const userId = currentUser(req).id;
    const user = db.prepare("SELECT display_name FROM users WHERE id = ? AND deleted_at IS NULL")
      .get(userId) as { display_name: string | null } | undefined;
    if (!user) throw notFound("Account not found");
    const alias = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
    const publicName = body.publicName ?? user.display_name ?? (alias ? `${alias.alias}@monad` : "Subtle Pay merchant");
    const now = Date.now();
    db.prepare(`INSERT INTO merchant_profiles (user_id, public_name, category, status, created_at, updated_at)
      VALUES (?, ?, ?, 'unverified', ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET public_name = excluded.public_name, category = excluded.category, updated_at = excluded.updated_at`)
      .run(userId, publicName, body.category, now, now);
    audit(userId, "merchant.enabled", { category: body.category }, req.ip);
    const profile = db.prepare("SELECT user_id AS userId, public_name AS publicName, category, status, created_at AS createdAt, updated_at AS updatedAt, verified_at AS verifiedAt FROM merchant_profiles WHERE user_id = ?")
      .get(userId);
    return { enabled: true, profile, verifiedBadge: false, message: "Merchant profile enabled. The yellow verified badge is shown only after staff approval." };
  });

  app.get("/merchant/autopay-applications", { preHandler: requireAuth }, async (req) => {
    const userId = currentUser(req).id;
    return db.prepare(`SELECT id, reason, status, created_at AS createdAt, reviewed_at AS reviewedAt, review_note AS reviewNote
      FROM merchant_autopay_applications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`).all(userId);
  });

  app.post("/merchant/autopay-applications", { preHandler: requireAuth, config: { rateLimit: { max: 3, timeWindow: 60_000 } } }, async (req) => {
    const body = applicationBody.parse(req.body);
    const userId = currentUser(req).id;
    const profile = db.prepare("SELECT status FROM merchant_profiles WHERE user_id = ?").get(userId) as { status: string } | undefined;
    if (!profile) throw badRequest("Enable a merchant profile before applying for Autopay.", "MERCHANT_REQUIRED");
    const pending = db.prepare("SELECT id FROM merchant_autopay_applications WHERE user_id = ? AND status = 'pending'").get(userId);
    if (pending) throw conflict("An Autopay application is already pending review.", "APPLICATION_PENDING");
    const id = newId();
    db.prepare("INSERT INTO merchant_autopay_applications (id, user_id, reason, status, created_at) VALUES (?, ?, ?, 'pending', ?)")
      .run(id, userId, body.reason, Date.now());
    audit(userId, "merchant.autopay_application.submitted", { applicationId: id }, req.ip);
    return { id, status: "pending", message: "Application submitted. Autopay remains disabled until approval." };
  });
}
