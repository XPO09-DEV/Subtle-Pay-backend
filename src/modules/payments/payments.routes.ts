import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { runIdempotent } from "../../middleware/idempotency.js";
import { assertPayableAsset } from "../assets/assets.service.js";
import { listPayments, sendPayment } from "./payments.service.js";

const sendBody = z.object({
  to: z.string().min(2).max(64),
  amount: z.union([z.string(), z.number()]),
  amountCurrency: z.string().length(3),
  note: z.string().max(140).optional(),
  asset: z.string().max(8).optional(),
});

export async function paymentRoutes(app: FastifyInstance): Promise<void> {
  app.post("/payments/send", { preHandler: requireAuth }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = sendBody.parse(req.body);
    assertPayableAsset(body.asset);
    const key = req.headers["idempotency-key"];
    return runIdempotent(currentUser(req).id, Array.isArray(key) ? key[0] : key, body, reply, () =>
      sendPayment(currentUser(req).id, body, req.ip)
    );
  });

  app.get("/payments", { preHandler: requireAuth }, async (req) => {
    const query = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(50),
      offset: z.coerce.number().int().min(0).max(100_000).default(0),
      status: z.enum(["pending", "submitted", "confirmed", "failed"]).optional(),
      direction: z.enum(["in", "out"]).optional(),
    }).parse(req.query);
    return listPayments(currentUser(req).id, query);
  });
}
