import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { getWalletView } from "./wallet.service.js";

export async function walletRoutes(app: FastifyInstance): Promise<void> {
  app.get("/wallet", { preHandler: requireAuth }, async (req) => {
    const query = z.object({ refresh: z.enum(["true", "false"]).optional() }).parse(req.query);
    return getWalletView(currentUser(req).id, query.refresh === "true");
  });
}