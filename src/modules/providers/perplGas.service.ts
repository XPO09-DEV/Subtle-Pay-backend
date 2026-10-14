import { config } from "../../config.js";

const CACHE_TTL_MS = 15_000;
const MAX_STALE_CACHE_MS = 120_000;
const MAX_FRESH_SAMPLE_AGE_MS = 60_000;
const MAX_REASONABLE_AMOUNT = 10n ** 30n;

type PerplBlockTimestamp = { b?: number; t?: number };
type PerplGasWire = {
  at?: PerplBlockTimestamp;
  h?: number;
  max?: string;
  p95?: string;
  p50?: string;
  min?: string;
  base?: string;
};
type PerplContextWire = {
  chain?: { chain_id?: number; gas?: PerplGasWire };
  markets?: unknown[];
  tokens?: unknown[];
};
export type PerplGasSnapshot = {
  provider: "perpl";
  chainId: number;
  headBlock: number | null;
  sampledAt: string | null;
  ageMs: number | null;
  fresh: boolean;
  baseFeePerGasWei: string;
  minPriorityFeePerGasWei: string;
  medianPriorityFeePerGasWei: string;
  p95PriorityFeePerGasWei: string;
  maxPriorityFeePerGasWei: string;
  marketCount: number;
  tokenCount: number;
};

type CachedSnapshot = Omit<PerplGasSnapshot, "ageMs" | "fresh"> & {
  fetchedAt: number;
  sampledAtMs: number | null;
};

let cached: CachedSnapshot | null = null;
let inFlight: Promise<CachedSnapshot> | null = null;

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function rawAmount(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new Error("Perpl gas response has an invalid " + name + " amount.");
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > MAX_REASONABLE_AMOUNT) {
    throw new Error("Perpl gas response has an out-of-range " + name + " amount.");
  }
  return parsed.toString();
}

async function loadContext(): Promise<CachedSnapshot> {
  const response = await fetch(config.PERPL_API_URL.replace(/\/+$/, "") + "/v1/pub/context", {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(3_500),
  });
  if (!response.ok) throw new Error("Perpl context returned HTTP " + response.status + ".");
  const payload = await response.json() as unknown as PerplContextWire;
  const chain = record(payload.chain);
  if (!chain || Number(chain.chain_id) !== 10143) {
    throw new Error("Perpl gas data did not identify Monad Testnet (chain ID 10143).");
  }
  const gas = record(chain.gas);
  if (!gas) throw new Error("Perpl context did not include a gas snapshot.");
  const at = record(gas.at);
  const sampledAtMs = typeof at?.t === "number" && Number.isFinite(at.t) && at.t > 0 && at.t <= 8.64e15
    ? at.t
    : null;
  const base = rawAmount(gas.base, "base fee");
  if (BigInt(base) === 0n) throw new Error("Perpl gas snapshot has a zero base fee.");

  return {
    provider: "perpl",
    chainId: 10143,
    headBlock: typeof gas.h === "number" && Number.isSafeInteger(gas.h) && gas.h >= 0 ? gas.h : null,
    sampledAt: sampledAtMs === null ? null : new Date(sampledAtMs).toISOString(),
    baseFeePerGasWei: base,
    minPriorityFeePerGasWei: rawAmount(gas.min, "minimum priority fee"),
    medianPriorityFeePerGasWei: rawAmount(gas.p50, "median priority fee"),
    p95PriorityFeePerGasWei: rawAmount(gas.p95, "95th percentile priority fee"),
    maxPriorityFeePerGasWei: rawAmount(gas.max, "maximum priority fee"),
    marketCount: Array.isArray(payload.markets) ? payload.markets.length : 0,
    tokenCount: Array.isArray(payload.tokens) ? payload.tokens.length : 0,
    fetchedAt: Date.now(),
    sampledAtMs,
  };
}

function present(snapshot: CachedSnapshot): PerplGasSnapshot {
  const ageMs = snapshot.sampledAtMs === null ? null : Date.now() - snapshot.sampledAtMs;
  const fresh = ageMs !== null && ageMs >= -30_000 && ageMs <= MAX_FRESH_SAMPLE_AGE_MS;
  const { fetchedAt: _fetchedAt, sampledAtMs: _sampledAtMs, ...publicFields } = snapshot;
  return { ...publicFields, ageMs: ageMs === null ? null : Math.max(0, ageMs), fresh };
}

/** Read public Perpl gas stats with request coalescing and a small cache. Returns null on provider failure. */
export async function getPerplGasSnapshot(): Promise<PerplGasSnapshot | null> {
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) return present(cached);
  if (!inFlight) {
    inFlight = loadContext()
      .then((snapshot) => {
        cached = snapshot;
        return snapshot;
      })
      .finally(() => {
        inFlight = null;
      });
  }
  try {
    return present(await inFlight);
  } catch {
    if (cached && Date.now() - cached.fetchedAt <= MAX_STALE_CACHE_MS) return present(cached);
    return null;
  }
}
