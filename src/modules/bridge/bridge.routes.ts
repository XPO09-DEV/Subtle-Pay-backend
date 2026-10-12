import type { FastifyInstance } from "fastify";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { serviceUnavailable } from "../../lib/errors.js";
import { audit } from "../../lib/audit.js";

/** Cross-chain settlement isn't implemented; fail closed instead of returning a simulated transfer. */
export async function bridgeRoutes(app: FastifyInstance): Promise<void> {
  app.post("/bridge/preview", { preHandler: requireAuth }, async (req) => {
    audit(currentUser(req).id, "bridge.unavailable_requested", undefined, req.ip);
    throw serviceUnavailable(
      "Cross-chain bridging is not enabled. No funds have been locked, bridged, or settled.",
      "CHAIN_UNAVAILABLE"
    );
  });
}
