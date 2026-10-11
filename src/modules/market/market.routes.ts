import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../../config.js";
import { badRequest, notFound, serviceUnavailable, tooManyRequests } from "../../lib/errors.js";

const CHAIN = "monad";
const CACHE_TTL_MS = 60_000;
const ALLOWLIST_TTL_MS = 5 * 60_000;

type CoinStatsCoin = {
  id: string;
  name?: string;
  symbol?: string;
  icon?: string | null;
  price?: number | null;
  priceChange1d?: number | null;
  contractAddress?: string | null;
  contractAddresses?: Array<{ blockchain?: string; address?: string; contractAddress?: string }>;
};

type CoinStatsCoinList = {
  meta?: Record<string, unknown>;
  result?: CoinStatsCoin[];
};

type CoinStatsChart = { result?: number[][] } | number[][];

const assetsQuerySchema = z.object({
  currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
  page: z.coerce.number().int().min(1).max(100).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(100),
});

const chartQuerySchema = z.object({
  period: z.enum(["24h", "1w", "1m", "3m", "6m", "1y", "all"]).default("24h"),
  currency: z.string().trim().regex(/^[A-Za-z]{3}$/).default("USD"),
});

const assetsCache = new Map<string, { expiresAt: number; payload: CoinStatsCoinList }>();
const chartCache = new Map<string, { expiresAt: number; payload: CoinStatsChart }>();
const allowedCoinIds = new Map<string, number>();

function coinStatsBase(): string {
  return config.COINSTATS_API_BASE_URL.replace(/\/+$/, "");
}

async function coinStatsJson<T>(path: string): Promise<T> {
  if (!config.COINSTATS_API_KEY.trim()) {
    throw serviceUnavailable("CoinStats API key is not configured on the backend", "CHAIN_UNAVAILABLE");
  }

  let response: Response;
  try {
    response = await fetch(coinStatsBase() + path, {
      headers: {
        Accept: "application/json",
        "X-API-KEY": config.COINSTATS_API_KEY.trim(),
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    throw serviceUnavailable("Could not reach CoinStats market data", "CHAIN_UNAVAILABLE", error);
  }

  if (response.status === 401 || response.status === 403) {
    throw serviceUnavailable("CoinStats rejected the configured API key; check COINSTATS_API_KEY", "CHAIN_UNAVAILABLE");
  }
  if (response.status === 429) {
    throw tooManyRequests(30, "CoinStats rate limit reached. Retry shortly.");
  }
  if (response.status === 404) {
    throw notFound("CoinStats has no chart data for this Monad asset and period");
  }
  if (!response.ok) {
    throw serviceUnavailable("CoinStats market request failed (" + response.status + ")", "CHAIN_UNAVAILABLE");
  }

  return response.json() as Promise<T>;
}

async function getMonadCoins(currency: string, page: number, limit: number): Promise<CoinStatsCoinList> {
  const key = currency.toUpperCase() + ":" + page + ":" + limit;
  const cached = assetsCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.payload;

  const params = new URLSearchParams({
    blockchains: CHAIN,
    currency: currency.toUpperCase(),
    page: String(page),
    limit: String(limit),
    sortBy: "marketCap",
    sortDir: "desc",
  });
  const payload = await coinStatsJson<CoinStatsCoinList>("/coins?" + params.toString());
  const now = Date.now();
  for (const coin of payload.result ?? []) {
    if (coin.id) allowedCoinIds.set(coin.id, now + ALLOWLIST_TTL_MS);
  }
  assetsCache.set(key, { expiresAt: now + CACHE_TTL_MS, payload });
  return payload;
}

async function assertMonadCoin(coinId: string): Promise<void> {
  const expiry = allowedCoinIds.get(coinId);
  if (expiry && expiry > Date.now()) return;

  // A chart request is only permitted if CoinStats confirms the ID under the Monad-only filter.
  const params = new URLSearchParams({
    blockchains: CHAIN,
    coinIds: coinId,
    currency: "USD",
    page: "1",
    limit: "1",
  });
  const payload = await coinStatsJson<CoinStatsCoinList>("/coins?" + params.toString());
  const isMonadAsset = (payload.result ?? []).some((coin) => coin.id === coinId);
  if (!isMonadAsset) throw notFound("This asset is not listed by CoinStats for the Monad blockchain");
  allowedCoinIds.set(coinId, Date.now() + ALLOWLIST_TTL_MS);
}

export async function marketRoutes(app: FastifyInstance): Promise<void> {
  app.get("/market/monad/assets", async (req, reply) => {
    const parsed = assetsQuerySchema.safeParse(req.query);
    if (!parsed.success) throw badRequest("Invalid market query parameters", "VALIDATION_ERROR");
    const { currency, page, limit } = parsed.data;
    const payload = await getMonadCoins(currency, page, limit);
    reply.header("Cache-Control", "private, max-age=60");
    return { provider: "coinstats", blockchain: CHAIN, ...payload };
  });

  app.get("/market/monad/charts/:coinId", async (req, reply) => {
    const params = req.params as { coinId?: string };
    const coinId = params.coinId?.trim() ?? "";
    if (!/^[a-zA-Z0-9._-]{1,120}$/.test(coinId)) {
      throw badRequest("Invalid CoinStats coin ID", "BAD_REQUEST");
    }
    const parsed = chartQuerySchema.safeParse(req.query);
    if (!parsed.success) throw badRequest("Invalid chart query parameters", "VALIDATION_ERROR");
    await assertMonadCoin(coinId);

    const { period, currency } = parsed.data;
    const key = coinId + ":" + period + ":" + currency.toUpperCase();
    const cached = chartCache.get(key);
    if (cached && cached.expiresAt > Date.now()) {
      reply.header("Cache-Control", "private, max-age=60");
      return cached.payload;
    }

    const query = new URLSearchParams({ period, currency: currency.toUpperCase() });
    const payload = await coinStatsJson<CoinStatsChart>("/coins/" + encodeURIComponent(coinId) + "/charts?" + query.toString());
    chartCache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, payload });
    reply.header("Cache-Control", "private, max-age=60");
    return payload;
  });
}
