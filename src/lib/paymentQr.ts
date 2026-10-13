import crypto from "node:crypto";
import { config } from "../config.js";

const qrKey = Buffer.from(
  crypto.hkdfSync(
    "sha256",
    Buffer.from(config.MASTER_KEY, "hex"),
    Buffer.from("subtle-pay/qr/salt/v1"),
    Buffer.from("subtle-pay/qr-signature/v1"),
    32
  )
);

export type PayQrCurrency = "USD" | "INR";
export type PayQrClaims = {
  v: 1;
  to: string;
  addr: string;
  chain: 10143;
  amount?: string;
  currency?: PayQrCurrency;
};

function serializedClaims(claims: PayQrClaims): string {
  return JSON.stringify({
    v: claims.v,
    to: claims.to,
    addr: claims.addr.toLowerCase(),
    chain: claims.chain,
    ...(claims.amount ? { amount: claims.amount, currency: claims.currency ?? "USD" } : {}),
  });
}

function signature(claims: PayQrClaims): string {
  return crypto.createHmac("sha256", qrKey).update(serializedClaims(claims)).digest("hex");
}

export function createPayQrPayload(address: string, amount?: string, currency: PayQrCurrency = "USD"): string {
  const claims: PayQrClaims = {
    v: 1,
    // The permanent receive QR points directly to the fixed wallet address.
    // The human-readable alias is metadata, so changing profile text can never
    // silently change the wallet's previously issued QR.
    to: address,
    addr: address,
    chain: 10143,
    ...(amount ? { amount, currency } : {}),
  };
  const params = new URLSearchParams({
    v: String(claims.v),
    to: claims.to,
    addr: claims.addr,
    chain: String(claims.chain),
    ...(claims.amount ? { amount: claims.amount, currency: claims.currency ?? "USD" } : {}),
    sig: signature(claims),
  });
  return `subtlepay://pay?${params.toString()}`;
}

export function verifyPayQrSignature(claims: PayQrClaims, actual: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(actual)) return false;
  const expected = Buffer.from(signature(claims), "hex");
  const supplied = Buffer.from(actual, "hex");
  return expected.length === supplied.length && crypto.timingSafeEqual(supplied, expected);
}
