import { config } from "../../config.js";
import { unprocessable } from "../../lib/errors.js";

export type PayAssetCode = "MON" | "USDC";
export interface PayAsset {
  code: PayAssetCode;
  name: string;
  chain: "monad-testnet";
  settles: true;
}
/** Only assets with an explicit server-side settlement path are payable. */
export function listAssets(): PayAsset[] {
  const assets: PayAsset[] = [{ code: "MON", name: "Monad Testnet MON", chain: "monad-testnet", settles: true }];
  if (config.STABLE_TOKEN_ADDRESS) assets.push({ code: "USDC", name: "Configured Monad Testnet USDC", chain: "monad-testnet", settles: true });
  return assets;
}
export function assertPayableAsset(code: string | undefined): PayAssetCode {
  const asset = (code ?? "MON").trim().toUpperCase();
  if (asset === "MON") return "MON";
  if (asset === "USDC" && config.STABLE_TOKEN_ADDRESS) return "USDC";
  throw unprocessable("This asset has no configured settlement contract on Monad Testnet. Only MON and configured USDC are payable.", "CHAIN_UNAVAILABLE");
}
