import type { FastifyInstance } from "fastify";
import { badRequest, serviceUnavailable } from "../../lib/errors.js";
import { z } from "zod";
import { getAnkrWalletAssets, getCoinStatsCharts, getCoinStatsCoin, getCoinStatsCoinList, getCoinStatsMarkets } from "./providers.service.js";

const addressQuery = z.object({
  address: z.string().trim().min(42).max(42),
  refresh: z.coerce.boolean().default(false),
});
const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  skip: z.coerce.number().int().min(0).max(100_000).default(0),
  currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
  coinIds: z.string().trim().max(2_000).optional(),
});
const searchQuery = z.object({ q: z.string().trim().min(2).max(80), currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD") });
const chartQuery = z.object({
  period: z.enum(["24h", "1w", "1m", "3m", "6m", "1y", "all"]).default("24h"),
  currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
});

function filterSearchPayload(payload: unknown, query: string): unknown {
  if (!payload || typeof payload !== "object") return payload;
  const envelope = payload as Record<string, unknown>;
  const field = Array.isArray(envelope.result) ? "result" : Array.isArray(envelope.coins) ? "coins" : "";
  if (!field) return payload;
  const needle = query.toLowerCase();
  const filtered = (envelope[field] as unknown[]).filter((row) => {
    if (!row || typeof row !== "object") return false;
    const coin = row as Record<string, unknown>;
    const scalar = [coin.id, coin.name, coin.symbol, coin.contractAddress];
    if (scalar.some((value) => typeof value === "string" && value.toLowerCase().includes(needle))) return true;
    return Array.isArray(coin.contractAddresses) && coin.contractAddresses.some((entry) => {
      if (typeof entry === "string") return entry.toLowerCase().includes(needle);
      return !!entry && typeof entry === "object" && Object.values(entry as Record<string, unknown>)
        .some((value) => typeof value === "string" && value.toLowerCase().includes(needle));
    });
  });
  return { ...envelope, [field]: filtered };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function coinRows(payload: unknown): Record<string, unknown>[] {
  if (Array.isArray(payload)) return payload.map(asRecord).filter((row): row is Record<string, unknown> => row !== null);
  const root = asRecord(payload);
  if (!root) return [];
  for (const key of ["result", "coins", "data", "items"]) {
    const value = root[key];
    if (Array.isArray(value)) return value.map(asRecord).filter((row): row is Record<string, unknown> => row !== null);
  }
  const nested = asRecord(root.result) ?? asRecord(root.data);
  if (nested) {
    for (const key of ["result", "coins", "data", "items"]) {
      if (Array.isArray(nested[key])) return (nested[key] as unknown[]).map(asRecord).filter((row): row is Record<string, unknown> => row !== null);
    }
  }
  return [];
}
function unwrapCoin(payload: unknown): Record<string, unknown> {
  let current: unknown = payload;
  for (let i = 0; i < 4; i++) {
    const object = asRecord(current);
    if (!object) break;
    const nested = asRecord(object.coin) ?? asRecord(object.result) ?? asRecord(object.data);
    if (!nested) return object;
    current = nested;
  }
  return asRecord(current) ?? {};
}
function platformForChain(raw: string): string | null {
  const value = raw.toLowerCase().replace(/[_\s]/g, "-");
  const mappings: Array<[string, string[]]> = [
    ["ethereum", ["ethereum", "eth", "ethereum-mainnet"]],
    ["binance-smart-chain", ["binance-smart-chain", "bsc", "bnb", "bnb-chain", "bnb-smart-chain"]],
    ["polygon-pos", ["polygon", "polygon-pos", "matic", "polygon-mainnet"]],
    ["arbitrum-one", ["arbitrum", "arbitrum-one"]],
    ["optimistic-ethereum", ["optimism", "optimistic-ethereum"]],
    ["base", ["base", "base-mainnet"]],
    ["avalanche", ["avalanche", "avalanche-c", "avalanche-c-chain"]],
    ["solana", ["solana", "sol"]],
    ["monad", ["monad", "monad-mainnet"]],
    ["tron", ["tron", "trx"]],
    ["the-open-network", ["the-open-network", "ton"]],
  ];
  for (const [platform, aliases] of mappings) {
    if (aliases.some((alias) => value === alias || value.includes(alias))) return platform;
  }
  return null;
}
function geckoDetails(payload: unknown, coinId: string): Record<string, unknown> {
  const coin = unwrapCoin(payload);
  const platforms: Record<string, string> = {};
  const oldPlatforms = asRecord(coin.platforms);
  if (oldPlatforms) {
    for (const [platform, address] of Object.entries(oldPlatforms)) if (typeof address === "string" && address) platforms[platform] = address;
  }
  const addAddress = (chain: unknown, address: unknown) => {
    if (typeof chain !== "string" || typeof address !== "string" || !address.trim()) return;
    const platform = platformForChain(chain);
    if (platform) platforms[platform] = address.trim();
  };
  const contracts = coin.contractAddresses;
  if (Array.isArray(contracts)) {
    for (const entryValue of contracts) {
      const entry = asRecord(entryValue);
      if (!entry) continue;
      addAddress(entry.blockchain ?? entry.chain ?? entry.network ?? entry.platform ?? entry.chainName,
        entry.contractAddress ?? entry.address ?? entry.tokenAddress);
    }
  } else if (asRecord(contracts)) {
    for (const [chain, address] of Object.entries(asRecord(contracts)!)) {
      if (typeof address === "string") addAddress(chain, address);
      else {
        const entry = asRecord(address);
        if (entry) addAddress(chain, entry.contractAddress ?? entry.address);
      }
    }
  }
  addAddress(coin.blockchain ?? coin.network ?? coin.assetPlatformId, coin.contractAddress ?? coin.address);
  return {
    ...coin,
    id: typeof coin.id === "string" ? coin.id : coinId,
    name: typeof coin.name === "string" ? coin.name : coinId,
    symbol: typeof coin.symbol === "string" ? coin.symbol : "",
    platforms,
  };
}
function geckoMarketRow(value: Record<string, unknown>): Record<string, unknown> {
  const coin = unwrapCoin(value);
  const price = Number(coin.price ?? coin.current_price);
  const change = Number(coin.priceChange1d ?? coin.priceChange24h ?? coin.price_change_percentage_24h);
  return {
    id: coin.id,
    symbol: coin.symbol,
    name: coin.name,
    image: coin.icon ?? coin.image ?? coin.thumbnail ?? null,
    current_price: Number.isFinite(price) ? price : null,
    price_change_percentage_24h: Number.isFinite(change) ? change : null,
    price_change_percentage_24h_in_currency: Number.isFinite(change) ? change : null,
  };
}
function chartRows(payload: unknown, depth = 0): unknown[] {
  if (Array.isArray(payload)) return payload;
  if (depth > 4) return [];
  const object = asRecord(payload);
  if (!object) return [];
  for (const key of ["result", "data", "chart", "charts", "prices", "points", "history", "series"]) {
    const value = object[key];
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") {
      const nested = chartRows(value, depth + 1);
      if (nested.length) return nested;
    }
  }
  return [];
}
function geckoPrices(payload: unknown): number[][] {
  const out: number[][] = [];
  for (const row of chartRows(payload)) {
    let stamp: number;
    let price: number;
    if (Array.isArray(row) && row.length >= 2) {
      stamp = Number(row[0]);
      price = Number(row[1]);
    } else {
      const point = asRecord(row);
      if (!point) continue;
      const timeValue = point.timestamp ?? point.time ?? point.date ?? point.t;
      stamp = typeof timeValue === "string" && !/^\d+(\.\d+)?$/.test(timeValue) ? Date.parse(timeValue) : Number(timeValue);
      price = Number(point.price ?? point.value ?? point.close ?? point.usd);
    }
    if (!Number.isFinite(stamp) || !Number.isFinite(price) || price <= 0) continue;
    if (stamp < 1_000_000_000_000) stamp *= 1000;
    out.push([stamp, price]);
  }
  return out.sort((a, b) => a[0] - b[0]);
}

export async function providerRoutes(app: FastifyInstance): Promise<void> {
  app.get("/api/wallet/assets", { config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = addressQuery.parse(req.query);
    const value = await getAnkrWalletAssets(query.address, query.refresh);
    return { assets: value.assets, updatedAt: value.updatedAt, partial: value.partial, cached: value.cached };
  });
  app.get("/market/search", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const query = searchQuery.parse(req.query);
    return filterSearchPayload(await getCoinStatsCoinList({ limit: 100, skip: 0, currency: query.currency, search: query.q }), query.q);
  });
  app.get("/market/coins", { config: { rateLimit: { max: 45, timeWindow: 60_000 } } }, async (req) =>
    getCoinStatsCoinList(listQuery.parse(req.query)));
  app.get("/market/coins/:coinId/charts", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const params = req.params as { coinId: string };
    const query = chartQuery.parse(req.query);
    return getCoinStatsCharts(params.coinId, query.period, query.currency);
  });
  app.get("/market/coins/:coinId", { config: { rateLimit: { max: 45, timeWindow: 60_000 } } }, async (req) => {
    const params = req.params as { coinId: string };
    const query = z.object({ currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD") }).parse(req.query);
    return getCoinStatsCoin(params.coinId, query.currency);
  });
  app.get("/market/markets", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async () => getCoinStatsMarkets());

  // CoinGecko-compatible adapters let the current widget use the CoinStats server proxy
  // without a market API key or provider-specific browser logic.
  app.get("/search", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({ query: z.string().trim().min(2).max(80) }).parse(req.query);
    const payload = await getCoinStatsCoinList({ limit: 100, skip: 0, currency: "USD", search: query.query });
    return { coins: coinRows(payload).map((coin) => ({
      id: coin.id, symbol: coin.symbol, name: coin.name,
      thumb: coin.icon ?? coin.image ?? coin.thumbnail ?? undefined,
    })) };
  });

  app.get("/coins/markets", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const query = z.object({
      ids: z.string().trim().min(1).max(2_000),
      vs_currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
      per_page: z.coerce.number().int().min(1).max(100).default(100),
    }).parse(req.query);
    const ids = [...new Set(query.ids.split(",").map((id) => id.trim()).filter(Boolean))].slice(0, 100);
    const payload = await getCoinStatsCoinList({
      limit: Math.max(1, Math.min(query.per_page, ids.length)),
      skip: 0,
      currency: query.vs_currency,
      coinIds: ids.join(","),
    });
    const byId = new Map(coinRows(payload).map((coin) => [String(coin.id ?? ""), geckoMarketRow(coin)]));
    const missing = ids.filter((id) => !byId.has(id));
    // CoinStats supports coinIds batch queries. If the provider omits a requested id,
    // individually request only those missing assets rather than fabricating a value.
    const details = await Promise.all(missing.slice(0, 10).map(async (id) => {
      try { return [id, geckoMarketRow(await getCoinStatsCoin(id, query.vs_currency) as Record<string, unknown>)] as const; }
      catch { return null; }
    }));
    for (const entry of details) if (entry) byId.set(entry[0], entry[1]);
    return ids.flatMap((id) => {
      const row = byId.get(id);
      return row ? [row] : [];
    });
  });

  app.get("/coins/:coinId/market_chart", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async (req) => {
    const params = req.params as { coinId: string };
    const query = z.object({
      vs_currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
      days: z.union([z.string(), z.coerce.number()]).default("1"),
    }).parse(req.query);
    const period = ({ "1": "24h", "7": "1w", "30": "1m", "90": "3m", "365": "1y", max: "all", all: "all" } as Record<string, string>)[String(query.days)];
    if (!period) throw badRequest("Unsupported chart range.");
    const payload = await getCoinStatsCharts(params.coinId, period, query.vs_currency);
    const prices = geckoPrices(payload);
    if (!prices.length) throw serviceUnavailable("CoinStats has no historical points for this coin and timeframe.", "RATES_UNAVAILABLE");
    return { prices };
  });

  app.get("/coins/:coinId", { config: { rateLimit: { max: 45, timeWindow: 60_000 } } }, async (req) => {
    const params = req.params as { coinId: string };
    const query = z.object({ vs_currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD") }).parse(req.query);
    return geckoDetails(await getCoinStatsCoin(params.coinId, query.vs_currency), params.coinId);
  });
}
