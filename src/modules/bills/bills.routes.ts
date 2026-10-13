import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import QRCode from "qrcode";
import { assertPayableAsset } from "../assets/assets.service.js";
import { createBill, getBill, payBill } from "./bills.service.js";
import { consumePaymentAuthorization } from "../auth/paymentAuth.service.js";

export async function billRoutes(app: FastifyInstance): Promise<void> {
  app.post("/bills", { preHandler: requireAuth }, async (req) => {
    const body = z
      .object({
        amount: z.union([z.string(), z.number()]),
        currency: z.string().length(3),
        note: z.string().max(140).optional(),
        asset: z.string().max(8).optional(),
      })
      .parse(req.body);
    assertPayableAsset(body.asset);
    return createBill(currentUser(req).id, body.amount, body.currency, body.note, req.ip);
  });

  app.get("/bills/:id", async (req) => getBill((req.params as { id: string }).id));

  app.get("/bills/:id/qr", async (req, reply) => {
    const bill = await getBill((req.params as { id: string }).id);
    const png = await QRCode.toBuffer(bill.qr, { width: 512, margin: 1 });
    return reply.type("image/png").send(png);
  });

  app.post("/bills/:id/pay", { preHandler: requireAuth, config: { rateLimit: { max: 10, timeWindow: 60_000 } } }, async (req) => {
    const body = z.object({ authorizationToken: z.string().min(40).max(64) }).parse(req.body);
    const userId = currentUser(req).id;
    consumePaymentAuthorization(userId, body.authorizationToken, req.ip);
    return payBill(userId, (req.params as { id: string }).id, req.ip);
  });
}
