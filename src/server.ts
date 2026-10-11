import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { config, isProd } from "./config.js";
import { closeDb } from "./db.js";
import { errorHandler, notFoundHandler } from "./lib/errors.js";
import { initPassword } from "./lib/password.js";
import { kmsSelfTest } from "./lib/kms.js";
import { authRoutes } from "./modules/auth/auth.routes.js";
import { aliasRoutes } from "./modules/alias/alias.routes.js";
import { ratesRoutes } from "./modules/rates/rates.routes.js";
import { walletRoutes } from "./modules/wallet/wallet.routes.js";
import { paymentRoutes } from "./modules/payments/payments.routes.js";
import { withdrawRoutes } from "./modules/withdraw/withdraw.routes.js";
import { contactRoutes } from "./modules/contacts/contacts.routes.js";
import { billRoutes } from "./modules/bills/bills.routes.js";
import { mandateRoutes } from "./modules/mandates/mandates.routes.js";
import { bridgeRoutes } from "./modules/bridge/bridge.routes.js";
import { assetRoutes } from "./modules/assets/assets.routes.js";

const app = Fastify({
  logger: {
    level: config.LOG_LEVEL,
    transport: isProd
      ? undefined
      : { target: "pino-pretty", options: { translateTime: "HH:MM:ss", ignore: "pid,hostname" } },
  },
  trustProxy: isProd,
  bodyLimit: 16 * 1024,
  requestIdHeader: "x-request-id",
});

app.setErrorHandler(errorHandler);
app.setNotFoundHandler(notFoundHandler);

await app.register(helmet, { contentSecurityPolicy: false });
await app.register(cors, { origin: config.CORS_ORIGINS, credentials: true });
await app.register(rateLimit, {
  max: config.RATE_LIMIT_MAX,
  timeWindow: config.RATE_LIMIT_WINDOW_SECONDS * 1000,
});

app.get("/health", async () => ({ ok: true }));
await app.register(authRoutes);
await app.register(aliasRoutes);
await app.register(ratesRoutes);
await app.register(walletRoutes);
await app.register(paymentRoutes);
await app.register(withdrawRoutes);
await app.register(contactRoutes);
await app.register(billRoutes);
await app.register(mandateRoutes);
await app.register(bridgeRoutes);
await app.register(assetRoutes);

const hashMs = await initPassword();
kmsSelfTest();
app.log.info({ hashMs }, "password hasher ready");

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  await app.close();
  closeDb();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.HOST, port: config.PORT });
app.log.info({ port: config.PORT }, "subtle pay api listening");
