import { formatEther, isAddress, type Address } from "viem";
import { config } from "../../config.js";
import { badRequest, serviceUnavailable } from "../../lib/errors.js";
import { getNativeBalance } from "../../chain/monad.js";

interface AnkrAsset {
  blockchain?: string; tokenName?: string; tokenSymbol?: string; balance?: string;
  balanceRawInteger?: string; balanceUsd?: string; tokenPrice?: string; tokenDecimals?: number;
  contractAddress?: string; thumbnail?: string; tokenType?: string;
}
interface AnkrEnvelope {
  error?: { message?: string; code?: number };
  result?: { assets?: AnkrAsset[]; nextPageToken?: string };
}
interface CacheEntry<T> { savedAt: number; value: T }
const WALLET_CACHE_MS = 60_000;
const MAX_CACHE_ENTRIES = 500;
const walletCache = new Map<string, CacheEntry<{ assets: AnkrAsset[]; updatedAt: string; partial: boolean }>>();
const walletInflight = new Map<string, Promise<{ assets: AnkrAsset[]; updatedAt: string; partial: boolean }>>();
const marketCache = new Map<string, CacheEntry<unknown>>();
const marketInflight = new Map<string, Promise<unknown>>();

function boundedCacheSet<T>(cache: Map<string, CacheEntry<T>>, key: string, value: T): void {
  cache.set(key, { savedAt: Date.now(), value });
  if (cache.size > MAX_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
}
function coinStatsBase(): string { return config.COINSTATS_API_BASE_URL.replace(/\/+$/, ""); }

async function readJson<T>(response: Response, provider: string): Promise<T> {
  if (!response.ok) {
    if (response.status === 429) throw serviceUnavailable(provider + " rate limit reached. Try again shortly.", "RATES_UNAVAILABLE");
    if (response.status === 401 || response.status === 403) {
      throw serviceUnavailable(provider + " rejected its configured server API key. Check the server environment.", "RATES_UNAVAILABLE");
    }
    throw serviceUnavailable(provider + " request failed (" + response.status + ").", "RATES_UNAVAILABLE");
  }
  try { return await response.json() as T; }
  catch { throw serviceUnavailable(provider + " returned invalid JSON.", "RATES_UNAVAILABLE"); }
}

async function loadAnkrAssets(address: string): Promise<{ assets: AnkrAsset[]; updatedAt: string; partial: boolean }> {
  if (!config.ANKR_API_KEY) throw serviceUnavailable("Ankr is not configured on the backend.", "CHAIN_UNAVAILABLE");
  const url = "https://rpc.ankr.com/multichain/" + encodeURIComponent(config.ANKR_API_KEY);
  const assets: AnkrAsset[] = [];
  let pageToken: string | undefined;
  let page = 0;
  try {
    do {
      const params: Record<string, unknown> = { walletAddress: address, nativeFirst: true, onlyWhitelisted: false, pageSize: 100 };
      if (pageToken) params.pageToken = pageToken;
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ankr_getAccountBalance", params, id: 1 }),
        signal: AbortSignal.timeout(10_000), cache: "no-store",
      });
      const envelope = await readJson<AnkrEnvelope>(response, "Ankr");
      if (envelope.error) throw serviceUnavailable(envelope.error.message || "Ankr could not read this wallet.", "CHAIN_UNAVAILABLE");
      if (!envelope.result || !Array.isArray(envelope.result.assets)) {
        throw serviceUnavailable("Ankr returned an unexpected wallet response.", "CHAIN_UNAVAILABLE");
      }
      assets.push(...envelope.result.assets);
      pageToken = envelope.result.nextPageToken || undefined;
      page++;
    } while (pageToken && page < 5);
  } catch (error) {
    if (error instanceof Error && "statusCode" in error) throw error;
    throw serviceUnavailable("Could not reach Ankr wallet indexing. Try again shortly.", "CHAIN_UNAVAILABLE", error);
  }

  let partial = Boolean(pageToken);
  try {
    const nativeBalance = await getNativeBalance(address as Address);
    if (nativeBalance > 0n) {
      const amount = Number(formatEther(nativeBalance));
      const present = assets.some((asset) => (asset.blockchain || "").toLowerCase() === "monad"
        && (asset.tokenSymbol || "").toUpperCase() === "MON"
        && (!asset.contractAddress || /^0x0{40}$/i.test(asset.contractAddress)));
      if (Number.isFinite(amount) && !present) assets.push({
        blockchain: "monad", tokenName: "Monad", tokenSymbol: "MON", balance: amount.toString(),
        balanceRawInteger: nativeBalance.toString(), tokenDecimals: 18, tokenType: "Native coin",
        contractAddress: "0x0000000000000000000000000000000000000000",
      });
    }
  } catch { partial = true; }

  const unique = new Map<string, AnkrAsset>();
  for (const asset of assets) {
    const chain = (asset.blockchain || "unknown").toLowerCase();
    const contract = asset.contractAddress?.trim().toLowerCase();
    const native = !contract || /^0x0{40}$/.test(contract);
    const id = chain + ":" + (native ? "native:" + (asset.tokenSymbol || "").toLowerCase() : contract);
    const previous = unique.get(id);
    if (!previous || Number(asset.balanceUsd || 0) > Number(previous.balanceUsd || 0)) unique.set(id, asset);
  }
  return { assets: [...unique.values()].filter((asset) => Number(asset.balance || 0) > 0), updatedAt: new Date().toISOString(), partial };
}

export async function getAnkrWalletAssets(rawAddress: string, force = false) {
  const address = rawAddress.trim();
  if (!isAddress(address)) throw badRequest("Enter a valid EVM wallet address.");
  const key = address.toLowerCase();
  const cached = walletCache.get(key);
  if (!force && cached && Date.now() - cached.savedAt < WALLET_CACHE_MS) return { ...cached.value, cached: true };
  const pending = !force ? walletInflight.get(key) : undefined;
  if (pending) return { ...(await pending), cached: true };
  const request = loadAnkrAssets(address);
  walletInflight.set(key, request);
  try {
    const value = await request;
    boundedCacheSet(walletCache, key, value);
    return { ...value, cached: false };
  } finally {
    if (walletInflight.get(key) === request) walletInflight.delete(key);
  }
}
function validateCoinId(id: string): string {
  const value = id.trim();
  if (!/^[A-Za-z0-9._:-]{1,100}$/.test(value)) throw badRequest("Invalid CoinStats coin id.");
  return value;
}
async function coinStatsRequest<T>(path: string, params: Record<string, string | number | undefined>, ttlMs: number): Promise<T> {
  if (!config.COINSTATS_API_KEY) throw serviceUnavailable("CoinStats is not configured on the backend.", "RATES_UNAVAILABLE");
  const pathPart = path.startsWith("/") ? path.slice(1) : path;
  const url = new URL(coinStatsBase() + "/" + pathPart);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") url.searchParams.set(key, String(value));
  }
  const cacheKey = url.pathname + url.search;
  const cached = marketCache.get(cacheKey);
  if (cached && Date.now() - cached.savedAt < ttlMs) return cached.value as T;
  const pending = marketInflight.get(cacheKey);
  if (pending) return pending as Promise<T>;
  const request = (async () => {
    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers: { accept: "application/json", "X-API-KEY": config.COINSTATS_API_KEY! },
        signal: AbortSignal.timeout(10_000), cache: "no-store",
      });
    } catch (error) {
      throw serviceUnavailable("Could not reach CoinStats market data. Try again shortly.", "RATES_UNAVAILABLE", error);
    }
    const value = await readJson<T>(response, "CoinStats");
    boundedCacheSet(marketCache, cacheKey, value);
    return value;
  })();
  marketInflight.set(cacheKey, request);
  try { return await request; }
  finally { if (marketInflight.get(cacheKey) === request) marketInflight.delete(cacheKey); }
}
export function getCoinStatsCoin(id: string, currency = "USD"): Promise<unknown> {
  return coinStatsRequest("coins/" + validateCoinId(id), { currency: currency.toUpperCase() }, 60_000);
}
export function getCoinStatsCoinList(options: { limit?: number; skip?: number; currency?: string; search?: string; coinIds?: string } = {}): Promise<unknown> {
  return coinStatsRequest("coins", {
    limit: options.limit ?? 100, skip: options.skip ?? 0, currency: (options.currency ?? "USD").toUpperCase(),
    search: options.search?.trim() || undefined, coinIds: options.coinIds,
  }, 60_000);
}
export function getCoinStatsCharts(id: string, period: string, currency = "USD"): Promise<unknown> {
  if (!new Set(["24h", "1w", "1m", "3m", "6m", "1y", "all"]).has(period)) throw badRequest("Unsupported chart period.");
  const ttl = 60_000;
  return coinStatsRequest("coins/" + validateCoinId(id) + "/charts", { period, currency: currency.toUpperCase() }, ttl);
}
export function getCoinStatsMarkets(): Promise<unknown> { return coinStatsRequest("markets", {}, 60_000); }
