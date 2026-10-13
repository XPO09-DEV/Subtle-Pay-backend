import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { config } from "../../config.js";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { db } from "../../db.js";
import { getWalletRow } from "../wallet/wallet.service.js";
import { badRequest, serviceUnavailable } from "../../lib/errors.js";
import { createPayQrPayload, verifyPayQrSignature, type PayQrClaims } from "../../lib/paymentQr.js";

const querySchema = z.object({
  amount: z.string().regex(/^(?:0|[1-9]\d{0,11})(?:\.\d{1,6})?$/).optional(),
  currency: z.enum(["USD", "INR"]).optional(),
});
const verifySchema = z.object({ payload: z.string().min(1).max(2048) });

function requireTestnet(): void {
  if (config.MONAD_CHAIN_ID !== 10143) {
    throw serviceUnavailable("Payment QR is available only on Monad Testnet (chain ID 10143).", "CHAIN_UNAVAILABLE");
  }
}
function permanentQr(userId: string, address: string): string {
  const existing = db.prepare("SELECT payload FROM wallet_qr WHERE user_id = ?").get(userId) as { payload: string } | undefined;
  if (existing) return existing.payload;
  const payload = createPayQrPayload(address);
  db.prepare("INSERT INTO wallet_qr (user_id, payload, chain_id, created_at) VALUES (?, ?, 10143, ?)")
    .run(userId, payload, Date.now());
  return payload;
}

export async function qrRoutes(app: FastifyInstance): Promise<void> {
  app.get("/qr/pay", { preHandler: requireAuth, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    requireTestnet();
    const query = querySchema.parse(req.query);
    if (query.amount !== undefined && Number(query.amount) <= 0) throw badRequest("Amount must be greater than zero", "INVALID_AMOUNT");
    if (query.amount === undefined && query.currency !== undefined) throw badRequest("Currency requires an amount.");

    const userId = currentUser(req).id;
    const wallet = getWalletRow(userId);
    const alias = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
    const payload = query.amount
      ? createPayQrPayload(wallet.address, query.amount, query.currency ?? "USD")
      : permanentQr(userId, wallet.address);
    const qr = db.prepare("SELECT created_at AS createdAt FROM wallet_qr WHERE user_id = ?").get(userId) as { createdAt: number } | undefined;
    return {
      payload,
      chainId: 10143,
      address: wallet.address,
      alias: alias?.alias ?? null,
      handle: alias ? `${alias.alias}@monad` : null,
      amount: query.amount ?? null,
      currency: query.amount ? query.currency ?? "USD" : null,
      permanent: query.amount === undefined,
      issuedAt: qr?.createdAt ?? null,
    };
  });

  app.post("/qr/verify", { config: { rateLimit: { max: 60, timeWindow: 60_000 } } }, async (req) => {
    requireTestnet();
    const { payload } = verifySchema.parse(req.body);
    let url: URL;
    try { url = new URL(payload); } catch { throw badRequest("Invalid payment QR payload"); }
    if (url.protocol !== "subtlepay:" || url.hostname !== "pay") throw badRequest("Invalid payment QR payload");

    const version = url.searchParams.get("v");
    const to = url.searchParams.get("to") ?? "";
    const addr = url.searchParams.get("addr") ?? "";
    const chain = url.searchParams.get("chain");
    const amount = url.searchParams.get("amount") ?? undefined;
    const currency = url.searchParams.get("currency") ?? undefined;
    const signature = url.searchParams.get("sig") ?? "";

    if (version !== "1" || chain !== "10143" || !isAddress(addr) || !to || to.length > 64) {
      throw badRequest("Invalid payment QR payload");
    }
    if (amount !== undefined && (!/^(?:0|[1-9]\d{0,11})(?:\.\d{1,6})?$/.test(amount) || Number(amount) <= 0 ||
      (currency !== "USD" && currency !== "INR"))) throw badRequest("Invalid payment QR payload");
    if (amount === undefined && currency !== undefined) throw badRequest("Invalid payment QR payload");
    const claims: PayQrClaims = {
      v: 1, to, addr, chain: 10143,
      ...(amount ? { amount, currency: currency as "USD" | "INR" } : {}),
    };
    if (!verifyPayQrSignature(claims, signature)) throw badRequest("Payment QR signature is invalid");
    return { valid: true, to, address: addr, chainId: 10143, amount: amount ?? null, currency: amount ? currency : null };
  });
}
