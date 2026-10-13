import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isAddress } from "viem";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../../config.js";
import { currentUser, requireAuth } from "../../middleware/auth.js";
import { badRequest, notFound, unprocessable } from "../../lib/errors.js";
import { getMe } from "../auth/auth.service.js";

const CHAIN_ID = 10143;
const QR_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const verifyBody = z.object({ payload: z.string().min(24).max(2048) });

function signingKey(): Buffer {
  // Domain-separated derivation keeps the QR MAC key separate from direct JWT use.
  return createHash("sha256")
    .update("subtle-pay/payment-qr/v1\0", "utf8")
    .update(Buffer.from(config.JWT_ACCESS_SECRET, "hex"))
    .digest();
}

function canonicalClaims(address: string, alias: string, issuedAt: number): string {
  return ["v1", String(CHAIN_ID), address.toLowerCase(), alias, String(issuedAt)].join("|");
}

function signature(address: string, alias: string, issuedAt: number): string {
  return createHmac("sha256", signingKey())
    .update(canonicalClaims(address, alias, issuedAt), "utf8")
    .digest("hex");
}

function invalidQr(): never {
  throw badRequest("Payment QR is invalid or expired", "BAD_REQUEST");
}

export async function qrRoutes(app: FastifyInstance): Promise<void> {
  app.get("/wallet/qr", { preHandler: requireAuth, config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    if (config.MONAD_CHAIN_ID !== CHAIN_ID) {
      throw unprocessable("Personal payment QR is only available on Monad Testnet (chain ID 10143).", "CHAIN_UNAVAILABLE");
    }

    const me = getMe(currentUser(req).id);
    const address = me.walletAddress;
    if (!address || !isAddress(address)) throw notFound("Account wallet not found", "NOT_FOUND");
    const alias = me.alias ?? "";
    const issuedAt = Date.now();
    const payload = new URL("subtlepay://pay");
    payload.searchParams.set("v", "1");
    payload.searchParams.set("to", alias ? `${alias}@monad` : address);
    payload.searchParams.set("addr", address);
    payload.searchParams.set("chain", String(CHAIN_ID));
    payload.searchParams.set("iat", String(issuedAt));
    if (alias) payload.searchParams.set("alias", alias);
    payload.searchParams.set("sig", signature(address, alias, issuedAt));

    return {
      payload: payload.toString(),
      address,
      alias: alias || null,
      chainId: CHAIN_ID,
      issuedAt,
      expiresAt: issuedAt + QR_TTL_MS,
    };
  });

  // Verification is intentionally public: a payer must be able to verify a recipient QR
  // without being authenticated as the recipient. It returns only public payment metadata.
  app.post("/qr/verify", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req, reply) => {
    reply.header("cache-control", "no-store, private");
    const body = verifyBody.parse(req.body);
    let url: URL;
    try {
      url = new URL(body.payload);
    } catch {
      return invalidQr();
    }
    if (url.protocol !== "subtlepay:" || url.hostname !== "pay" ||
        url.searchParams.get("v") !== "1" ||
        url.searchParams.get("chain") !== String(CHAIN_ID)) {
      return invalidQr();
    }

    const address = url.searchParams.get("addr") ?? "";
    const alias = url.searchParams.get("alias") ?? "";
    const to = url.searchParams.get("to") ?? "";
    const issuedAtRaw = url.searchParams.get("iat") ?? "";
    const suppliedSignature = url.searchParams.get("sig") ?? "";
    const issuedAt = Number(issuedAtRaw);
    const now = Date.now();

    if (!isAddress(address) ||
        (alias && !/^[a-z0-9_]{3,20}$/.test(alias)) ||
        to !== (alias ? `${alias}@monad` : address) ||
        !/^\\d{13}$/.test(issuedAtRaw) ||
        !Number.isSafeInteger(issuedAt) ||
        issuedAt > now + 30_000 ||
        now - issuedAt > QR_TTL_MS ||
        !/^[a-f0-9]{64}$/.test(suppliedSignature)) {
      return invalidQr();
    }

    const expected = Buffer.from(signature(address, alias, issuedAt), "hex");
    const received = Buffer.from(suppliedSignature, "hex");
    if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
      return invalidQr();
    }

    return {
      to,
      address,
      alias: alias || null,
      chainId: CHAIN_ID,
      verified: true as const,
      expiresAt: issuedAt + QR_TTL_MS,
    };
  });
}
