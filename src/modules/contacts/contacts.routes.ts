import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { deleteContact, listContacts, saveContact } from "./contacts.service.js";

export async function contactRoutes(app: FastifyInstance): Promise<void> {
  app.get("/contacts", { preHandler: requireAuth }, async (req) => listContacts(currentUser(req).id));
  app.post("/contacts", { preHandler: requireAuth }, async (req) => {
    const body = z.object({
      name: z.string().min(1).max(32),
      accountId: z.string().min(10).max(40).optional(),
      address: z.string().regex(/^0x[0-9a-fA-F]{40}$/).optional(),
      alias: z.string().trim().min(2).max(32).optional(),
    }).parse(req.body);
    return saveContact(currentUser(req).id, body.name, body, req.ip);
  });
  app.delete("/contacts/:name", { preHandler: requireAuth }, async (req) => {
    const { name } = req.params as { name: string };
    return deleteContact(currentUser(req).id, name);
  });
}
