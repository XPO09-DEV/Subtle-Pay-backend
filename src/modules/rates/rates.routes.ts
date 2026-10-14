import type { FastifyInstance } from "fastify";
import { getRates, listCurrencies, quote, tokenPrice } from "./rates.service.js";
import { getGasPriceInfo } from "../../chain/monad.js";

export async function ratesRoutes(app: FastifyInstance): Promise<void> {
  app.get("/gas/price", { config: { rateLimit: { max: 30, timeWindow: 60_000 } } }, async () => getGasPriceInfo());

  app.get("/rates", async (req) => {
    const query = req.query as { currency?: string };
    return getRates(query.currency ?? "USD");
  });

  app.get("/rates/currencies", async () => ({ currencies: listCurrencies() }));

  app.get("/rates/quote", async (req) => {
    const query = req.query as { from?: string; to?: string; amount?: string };
    return quote(query.from ?? "USD", query.to ?? "INR", query.amount ?? "1");
  });

  app.get("/rates/token", async (req) => {
    const query = req.query as { currency?: string; amount?: string };
    return tokenPrice(query.currency ?? "USD", query.amount ?? "1");
  });
}
