import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { config } from "../../config.js";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { db } from "../../db.js";
import { getWalletRow } from "../wallet/wallet.service.js";
import { badRequest, serviceUnavailable } from "../../lib/errors.js";

const qrKey = Buffer.from(crypto.hkdfSync("sha256", Buffer.from(config.MASTER_KEY, "hex"), Buffer.from("subtle-pay/qr/salt/v1"), Buffer.from("subtle-pay/qr-signature/v1"), 32));
const querySchema = z.object({ amount: z.string().regex(/^(?:0|[1-9]\d{0,11})(?:\.\d{1,6})?$/).optional(), currency: z.enum(["USD", "INR"]).optional() });
const verifySchema = z.object({ payload: z.string().min(1).max(2048) });
type QrClaims = { v: 1; to: string; addr: string; chain: 10143; amount?: string; currency?: "USD" | "INR" };
function sign(claims: QrClaims): string {
  const serialized = JSON.stringify({ v: claims.v, to: claims.to, addr: claims.addr.toLowerCase(), chain: claims.chain, ...(claims.amount ? { amount: claims.amount, currency: claims.currency ?? "USD" } : {}) });
  return crypto.createHmac("sha256", qrKey).update(serialized).digest("hex");
}
function safeSignatureEqual(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(actual)) return false;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}
function requireTestnet(): void {
  if (config.MONAD_CHAIN_ID !== 10143) throw serviceUnavailable("Payment QR is available only on Monad Testnet (chain ID 10143).", "CHAIN_UNAVAILABLE");
}
export async function qrRoutes(app: FastifyInstance): Promise<void> {
  app.get("/qr/pay", { preHandler: requireAuth, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    requireTestnet();
    const query = querySchema.parse(req.query);
    if (query.amount !== undefined && Number(query.amount) <= 0) throw badRequest("Amount must be greater than zero", "INVALID_AMOUNT");
    const userId = currentUser(req).id;
    const wallet = getWalletRow(userId);
    const alias = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
    const claims: QrClaims = { v: 1, to: alias?.alias ?? wallet.address, addr: wallet.address, chain: 10143, ...(query.amount ? { amount: query.amount, currency: query.currency ?? "USD" } : {}) };
    const params = new URLSearchParams({ v: String(claims.v), to: claims.to, addr: claims.addr, chain: String(claims.chain), ...(claims.amount ? { amount: claims.amount, currency: claims.currency ?? "USD" } : {}), sig: sign(claims) });
    return { payload: `subtlepay://pay?${params.toString()}`, chainId: 10143, address: wallet.address, alias: alias?.alias ?? null, amount: claims.amount ?? null, currency: claims.currency ?? null };
  });
  app.post("/qr/verify", { config: { rateLimit: { max: 60, timeWindow: 60_000 } } }, async (req) => {
    requireTestnet();
    const { payload } = verifySchema.parse(req.body);
    let url: URL;
    try { url = new URL(payload); } catch { throw badRequest("Invalid payment QR payload"); }
    if (url.protocol !== "subtlepay:" || url.hostname !== "pay") throw badRequest("Invalid payment QR payload");
    const version = url.searchParams.get("v"), to = url.searchParams.get("to") ?? "", addr = url.searchParams.get("addr") ?? "";
    const chain = url.searchParams.get("chain"), amount = url.searchParams.get("amount") ?? undefined;
    const currency = url.searchParams.get("currency") ?? undefined, signature = url.searchParams.get("sig") ?? "";
    if (version !== "1" || chain !== "10143" || !isAddress(addr) || !to || to.length > 64) throw badRequest("Invalid payment QR payload");
    if (amount !== undefined && (!/^(?:0|[1-9]\d{0,11})(?:\.\d{1,6})?$/.test(amount) || Number(amount) <= 0 || (currency !== "USD" && currency !== "INR"))) throw badRequest("Invalid payment QR payload");
    if (amount === undefined && currency !== undefined) throw badRequest("Invalid payment QR payload");
    const claims: QrClaims = { v: 1, to, addr, chain: 10143, ...(amount ? { amount, currency: currency as "USD" | "INR" } : {}) };
    if (!safeSignatureEqual(signature, sign(claims))) throw badRequest("Payment QR signature is invalid");
    return { valid: true, to, address: addr, chainId: 10143, amount: amount ?? null, currency: amount ? currency : null };
  });
}
