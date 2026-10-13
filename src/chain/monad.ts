import { createPublicClient, createWalletClient, erc20Abi, formatEther, formatUnits, http, parseEther, type Address, type Hash } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "../config.js";
import { serviceUnavailable } from "../lib/errors.js";

export const publicClient = createPublicClient({ transport: http(config.MONAD_RPC_URL, { timeout: 12_000, retryCount: 1 }) });
let verifiedChainAt = 0;
let chainCheck: Promise<void> | null = null;
const CHAIN_CHECK_TTL_MS = 15_000;

/** Fail closed if the configured RPC is not actually Monad Testnet, not merely labelled as such. */
export async function assertMonadTestnet(): Promise<void> {
  if (config.MONAD_CHAIN_ID !== 10143) throw serviceUnavailable("Subtle Pay is locked to Monad Testnet (chain ID 10143).", "CHAIN_UNAVAILABLE");
  if (Date.now() - verifiedChainAt < CHAIN_CHECK_TTL_MS) return;
  if (!chainCheck) {
    chainCheck = (async () => {
      let chainId: number;
      try { chainId = await publicClient.getChainId(); }
      catch (err) { throw serviceUnavailable("Monad Testnet RPC is unavailable.", "CHAIN_UNAVAILABLE", err); }
      if (chainId !== 10143) throw serviceUnavailable("The configured RPC is not Monad Testnet (chain ID 10143).", "CHAIN_UNAVAILABLE");
      verifiedChainAt = Date.now();
    })().finally(() => { chainCheck = null; });
  }
  await chainCheck;
}
const relayer = privateKeyToAccount(config.RELAYER_PRIVATE_KEY as `0x${string}`);
export function formatMon(wei: bigint): string { return formatEther(wei); }
export function formatToken(amount: bigint, decimals = 6): string { return formatUnits(amount, decimals); }

export async function getNativeBalance(address: Address): Promise<bigint> {
  try { await assertMonadTestnet(); return await publicClient.getBalance({ address }); }
  catch (err) { throw serviceUnavailable("Monad is unreachable. Try again in a moment.", "CHAIN_UNAVAILABLE", err); }
}
export async function getTokenBalance(address: Address): Promise<bigint | null> {
  if (!config.STABLE_TOKEN_ADDRESS) return null;
  try {
    await assertMonadTestnet();
    return await publicClient.readContract({ address: config.STABLE_TOKEN_ADDRESS as Address, abi: erc20Abi, functionName: "balanceOf", args: [address] });
  } catch (err) { throw serviceUnavailable("Could not read token balance", "CHAIN_UNAVAILABLE", err); }
}
function walletClient(privateKeyHex: `0x${string}`) {
  return createWalletClient({ account: privateKeyToAccount(privateKeyHex), transport: http(config.MONAD_RPC_URL, { timeout: 20_000, retryCount: 0 }) });
}
export async function sendNative(privateKeyHex: `0x${string}`, to: Address, value: bigint): Promise<Hash> {
  try { await assertMonadTestnet(); return await walletClient(privateKeyHex).sendTransaction({ to, value, chain: null }); }
  catch (err) { throw serviceUnavailable("Payment could not be submitted to Monad", "CHAIN_UNAVAILABLE", err); }
}
export async function sendToken(privateKeyHex: `0x${string}`, to: Address, amount: bigint): Promise<Hash> {
  if (!config.STABLE_TOKEN_ADDRESS) throw serviceUnavailable("Stable token is not configured", "CHAIN_UNAVAILABLE");
  try {
    await assertMonadTestnet();
    return await walletClient(privateKeyHex).writeContract({ address: config.STABLE_TOKEN_ADDRESS as Address, abi: erc20Abi, functionName: "transfer", args: [to, amount], chain: null });
  } catch (err) { throw serviceUnavailable("Token transfer could not be submitted", "CHAIN_UNAVAILABLE", err); }
}
/** Relayer drips a little testnet MON so a fresh wallet can pay gas. */
export async function ensureGas(address: Address): Promise<void> {
  const bal = await getNativeBalance(address);
  if (bal >= parseEther("0.01")) return;
  try {
    await assertMonadTestnet();
    const hash = await createWalletClient({ account: relayer, transport: http(config.MONAD_RPC_URL, { timeout: 20_000, retryCount: 0 }) })
      .sendTransaction({ to: address, value: parseEther("0.02"), chain: null });
    await publicClient.waitForTransactionReceipt({ hash, timeout: 20_000 });
  } catch (err) {
    throw serviceUnavailable("Could not fund gas. Fund the relayer at the faucet and retry.", "CHAIN_UNAVAILABLE", err);
  }
}
export async function waitConfirmed(hash: Hash): Promise<"confirmed" | "failed" | "submitted"> {
  try { await assertMonadTestnet(); const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 12_000 }); return receipt.status === "success" ? "confirmed" : "failed"; }
  catch { return "submitted"; }
}
/** Read-only receipt probe used by the transaction reconciler. A missing receipt is not a failure. */
export async function getReceiptStatus(hash: Hash): Promise<"confirmed" | "failed" | null> {
  try { await assertMonadTestnet(); const receipt = await publicClient.getTransactionReceipt({ hash }); return receipt.status === "success" ? "confirmed" : "failed"; }
  catch { return null; }
}
