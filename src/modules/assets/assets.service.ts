import { unprocessable } from "../../lib/errors.js";

export interface PayAsset {
  code: "MON";
  name: string;
  chain: "monad-testnet";
  settles: true;
}
/** This build deliberately exposes only the native Monad Testnet token. */
export function listAssets(): PayAsset[] {
  return [{ code: "MON", name: "Monad Testnet MON", chain: "monad-testnet", settles: true }];
}
export function assertPayableAsset(code: string | undefined): PayAsset["code"] {
  const asset = (code ?? "MON").trim().toUpperCase();
  if (asset !== "MON") throw unprocessable("Only free native MON on Monad Testnet (chain ID 10143) is enabled in this hackathon build.", "CHAIN_UNAVAILABLE");
  return "MON";
}
