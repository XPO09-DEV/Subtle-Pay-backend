import type { FastifyInstance } from "fastify";
import { requireAuth } from "../../middleware/auth.js";
import { withdrawalsUnavailable } from "./withdraw.service.js";

export async function withdrawRoutes(app: FastifyInstance): Promise<void> {
  // Do not create a fake "completed" withdrawal until a real payout provider is integrated.
  app.post("/withdraw", { preHandler: requireAuth }, async () => withdrawalsUnavailable());
}
