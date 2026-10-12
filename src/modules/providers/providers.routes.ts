import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { getAnkrWalletAssets, getCoinStatsCharts, getCoinStatsCoin, getCoinStatsCoinList, getCoinStatsMarkets } from "./providers.service.js";

const addressQuery = z.object({ address: z.string().trim().min(42).max(42) });
const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  skip: z.coerce.number().int().min(0).max(100_000).default(0),
  currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
  coinIds: z.string().trim().max(2_000).optional(),
});
const searchQuery = z.object({ q: z.string().trim().min(2).max(80), currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD") });
const chartQuery = z.object({ period: z.enum(["24h", "1w", "1m", "3m", "6m", "1y", "all"]).default("24h") });

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
export async function providerRoutes(app: FastifyInstance): Promise<void> {
  app.get("/api/wallet/assets", { config: { rateLimit: { max: 20, timeWindow: 60_000 } } }, async (req) => {
    const query = addressQuery.parse(req.query);
    const value = await getAnkrWalletAssets(query.address);
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
    return getCoinStatsCharts(params.coinId, query.period);
  });
  app.get("/market/coins/:coinId", { config: { rateLimit: { max: 45, timeWindow: 60_000 } } }, async (req) => {
    const params = req.params as { coinId: string };
    return getCoinStatsCoin(params.coinId);
  });
  app.get("/market/markets", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async () => getCoinStatsMarkets());
}
