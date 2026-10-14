import { createPublicClient, createWalletClient, erc20Abi, formatEther, formatUnits, http, parseEther, type Address, type Hash } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "../config.js";
import { serviceUnavailable } from "../lib/errors.js";
import { getPerplGasSnapshot, type PerplGasSnapshot } from "../modules/providers/perplGas.service.js";

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


type FeeOverrides =
  | { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }
  | { gasPrice: bigint };
type RpcFeeEstimate = Awaited<ReturnType<typeof publicClient.estimateFeesPerGas>>;
type GasFeePolicy = {
  overrides?: FeeOverrides;
  source: "perpl+monad-rpc" | "perpl" | "monad-rpc" | "rpc-auto";
  rpcAvailable: boolean;
  perpl: PerplGasSnapshot | null;
};

const MAX_PERPL_FEE_WEI = 10n ** 15n;
const MAX_FALLBACK_PRIORITY_FEE_WEI = 100_000_000_000n; // 100 gwei hard ceiling when RPC fee estimation is unavailable.
const MIN_PRIORITY_FEE_WEI = 100_000_000n; // 0.1 gwei lower bound only used to bound Perpl's suggested tip.

function bigintOrZero(value: string | undefined): bigint {
  if (!value || !/^\d+$/.test(value)) return 0n;
  try { return BigInt(value); } catch { return 0n; }
}
function minBigInt(a: bigint, b: bigint): bigint { return a < b ? a : b; }
function maxBigInt(a: bigint, b: bigint): bigint { return a > b ? a : b; }

function validPerplFees(snapshot: PerplGasSnapshot | null): snapshot is PerplGasSnapshot {
  if (!snapshot || !snapshot.fresh || snapshot.chainId !== 10143) return false;
  const base = bigintOrZero(snapshot.baseFeePerGasWei);
  const p95 = bigintOrZero(snapshot.p95PriorityFeePerGasWei);
  // Monad fee units are wei; a sub-gwei "base" almost certainly indicates an incompatible payload unit.
  return base >= 1_000_000_000n && p95 > 0n && base <= MAX_PERPL_FEE_WEI && p95 <= MAX_PERPL_FEE_WEI;
}

function chooseGasFeePolicy(rpcFees: RpcFeeEstimate | null, perpl: PerplGasSnapshot | null): GasFeePolicy {
  const rpcAvailable = rpcFees !== null;

  if (rpcFees && "maxFeePerGas" in rpcFees && "maxPriorityFeePerGas" in rpcFees
      && typeof rpcFees.maxFeePerGas === "bigint" && typeof rpcFees.maxPriorityFeePerGas === "bigint") {
    const rpcMaxFee = rpcFees.maxFeePerGas;
    const rpcPriority = rpcFees.maxPriorityFeePerGas;
    let maxFeePerGas = rpcMaxFee;
    let maxPriorityFeePerGas = rpcPriority;
    let source: GasFeePolicy["source"] = "monad-rpc";

    if (validPerplFees(perpl)) {
      const base = bigintOrZero(perpl.baseFeePerGasWei);
      const p95 = bigintOrZero(perpl.p95PriorityFeePerGasWei);
      // Treat Perpl as a second opinion only. Ignore large discrepancies rather than
      // allowing a stale/malformed provider response to inflate a user's fee.
      if (base <= rpcMaxFee * 2n && p95 <= rpcMaxFee * 2n) {
        const boundedTip = minBigInt(p95, maxBigInt(rpcPriority * 3n, MIN_PRIORITY_FEE_WEI));
        if (boundedTip > rpcPriority) {
          const perplMaxFee = base * 2n + boundedTip;
          const boundedMaxFee = minBigInt(perplMaxFee, rpcMaxFee * 2n);
          maxPriorityFeePerGas = boundedTip;
          maxFeePerGas = maxBigInt(rpcMaxFee, boundedMaxFee);
          maxPriorityFeePerGas = minBigInt(maxPriorityFeePerGas, maxFeePerGas);
          if (maxFeePerGas > rpcMaxFee || maxPriorityFeePerGas > rpcPriority) source = "perpl+monad-rpc";
        }
      }
    }
    return { overrides: { maxFeePerGas, maxPriorityFeePerGas }, source, rpcAvailable, perpl };
  }

  if (rpcFees && "gasPrice" in rpcFees && typeof rpcFees.gasPrice === "bigint") {
    let gasPrice = rpcFees.gasPrice;
    let source: GasFeePolicy["source"] = "monad-rpc";
    if (validPerplFees(perpl)) {
      const base = bigintOrZero(perpl.baseFeePerGasWei);
      const p95 = bigintOrZero(perpl.p95PriorityFeePerGasWei);
      if (base <= gasPrice * 2n && p95 <= gasPrice * 2n) {
        const candidate = base + minBigInt(p95, maxBigInt(gasPrice * 3n, MIN_PRIORITY_FEE_WEI));
        const boundedCandidate = minBigInt(candidate, gasPrice * 2n);
        if (boundedCandidate > gasPrice) {
          gasPrice = boundedCandidate;
          source = "perpl+monad-rpc";
        }
      }
    }
    return { overrides: { gasPrice }, source, rpcAvailable, perpl };
  }

  // Last-resort fee policy: only use Perpl's recent, testnet-validated snapshot
  // when the RPC cannot estimate fees, with a strict absolute bound.
  if (validPerplFees(perpl)) {
    const base = bigintOrZero(perpl.baseFeePerGasWei);
    const tip = minBigInt(bigintOrZero(perpl.p95PriorityFeePerGasWei), MAX_FALLBACK_PRIORITY_FEE_WEI);
    const maxFee = base * 2n + tip;
    if (maxFee > 0n && maxFee <= MAX_PERPL_FEE_WEI && maxFee >= tip) {
      return {
        overrides: { maxFeePerGas: maxFee, maxPriorityFeePerGas: tip },
        source: "perpl",
        rpcAvailable: false,
        perpl,
      };
    }
  }

  // Leave fee selection to viem if neither source has a safe current estimate.
  return { overrides: undefined, source: "rpc-auto", rpcAvailable, perpl };
}

async function loadGasFeePolicy(): Promise<GasFeePolicy> {
  const [rpcFees, perpl] = await Promise.all([
    publicClient.estimateFeesPerGas().catch(() => null),
    getPerplGasSnapshot(),
  ]);
  return chooseGasFeePolicy(rpcFees, perpl);
}

/** Public diagnostic quote for the currently configured Monad Testnet. */
export async function getGasPriceInfo() {
  await assertMonadTestnet();
  const policy = await loadGasFeePolicy();
  const overrides = policy.overrides;
  const feeFields = overrides && "gasPrice" in overrides
    ? { gasPriceWei: overrides.gasPrice.toString(), maxFeePerGasWei: null, maxPriorityFeePerGasWei: null }
    : overrides
      ? { gasPriceWei: null, maxFeePerGasWei: overrides.maxFeePerGas.toString(), maxPriorityFeePerGasWei: overrides.maxPriorityFeePerGas.toString() }
      : { gasPriceWei: null, maxFeePerGasWei: null, maxPriorityFeePerGasWei: null };

  return {
    chainId: config.MONAD_CHAIN_ID,
    network: "Monad Testnet",
    source: policy.source,
    rpcEstimateAvailable: policy.rpcAvailable,
    feeOverridesAppliedToNewTransfers: Boolean(overrides),
    ...feeFields,
    perpl: policy.perpl
      ? {
          available: true,
          chainId: policy.perpl.chainId,
          fresh: policy.perpl.fresh,
          headBlock: policy.perpl.headBlock,
          sampledAt: policy.perpl.sampledAt,
          ageMs: policy.perpl.ageMs,
          baseFeePerGasWei: policy.perpl.baseFeePerGasWei,
          minPriorityFeePerGasWei: policy.perpl.minPriorityFeePerGasWei,
          medianPriorityFeePerGasWei: policy.perpl.medianPriorityFeePerGasWei,
          p95PriorityFeePerGasWei: policy.perpl.p95PriorityFeePerGasWei,
          maxPriorityFeePerGasWei: policy.perpl.maxPriorityFeePerGasWei,
          marketCount: policy.perpl.marketCount,
          tokenCount: policy.perpl.tokenCount,
        }
      : { available: false, chainId: 10143 },
    updatedAt: new Date().toISOString(),
    note: "Perpl is a bounded second opinion for gas pricing. Monad RPC estimates remain primary; stale or out-of-range Perpl samples are ignored. Actual gas used depends on the transaction and recipient.",
  };
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
  try {
    await assertMonadTestnet();
    const feePolicy = await loadGasFeePolicy();
    return await walletClient(privateKeyHex).sendTransaction({
      to,
      value,
      ...(feePolicy.overrides ?? {}),
      chain: null,
    });
  } catch (err) {
    throw serviceUnavailable("Payment could not be submitted to Monad", "CHAIN_UNAVAILABLE", err);
  }
}
export async function sendToken(privateKeyHex: `0x${string}`, to: Address, amount: bigint): Promise<Hash> {
  if (!config.STABLE_TOKEN_ADDRESS) throw serviceUnavailable("Stable token is not configured", "CHAIN_UNAVAILABLE");
  try {
    await assertMonadTestnet();
    const feePolicy = await loadGasFeePolicy();
    return await walletClient(privateKeyHex).writeContract({
      address: config.STABLE_TOKEN_ADDRESS as Address,
      abi: erc20Abi,
      functionName: "transfer",
      args: [to, amount],
      ...(feePolicy.overrides ?? {}),
      chain: null,
    });
  } catch (err) { throw serviceUnavailable("Token transfer could not be submitted", "CHAIN_UNAVAILABLE", err); }
}
/** Relayer drips a little testnet MON so a fresh wallet can pay gas. */
export async function ensureGas(address: Address): Promise<void> {
  const bal = await getNativeBalance(address);
  if (bal >= parseEther("0.01")) return;
  try {
    await assertMonadTestnet();
    const feePolicy = await loadGasFeePolicy();
    const hash = await createWalletClient({ account: relayer, transport: http(config.MONAD_RPC_URL, { timeout: 20_000, retryCount: 0 }) })
      .sendTransaction({ to: address, value: parseEther("0.02"), ...(feePolicy.overrides ?? {}), chain: null });
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


/** Read confirmed on-chain execution cost. Returns null until a receipt is available. */
export async function getTransactionFeeDetails(hash: Hash): Promise<{
  gasUsed: string;
  effectiveGasPriceWei: string;
  feePaidWei: string;
} | null> {
  try {
    await assertMonadTestnet();
    const receipt = await publicClient.getTransactionReceipt({ hash });
    const effectiveGasPrice = receipt.effectiveGasPrice;
    if (typeof effectiveGasPrice !== "bigint" || receipt.gasUsed < 0n) return null;
    return {
      gasUsed: receipt.gasUsed.toString(),
      effectiveGasPriceWei: effectiveGasPrice.toString(),
      feePaidWei: (receipt.gasUsed * effectiveGasPrice).toString(),
    };
  } catch {
    return null;
  }
}
