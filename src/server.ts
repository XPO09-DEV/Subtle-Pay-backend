import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { config, isProd } from "./config.js";
import { closeDb } from "./db.js";
import { migrateTracking } from "./migrations/005-login-fund-holds-transaction-events.js";
import { migrateWalletFeatures } from "./migrations/006-wallet-security-and-merchants.js";
import { migratePaymentAuthorizationIntent } from "./migrations/007-payment-authorization-intent.js";
import { migrateAccountSettingsExtensions } from "./migrations/008-account-settings-extensions.js";
import { migrateWebAuthnPasskeys } from "./migrations/009-webauthn-passkeys.js";
import { migrateTransactionGasMetadata } from "./migrations/010-transaction-gas-metadata.js";
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
import { providerRoutes } from "./modules/providers/providers.routes.js";
import { adminRoutes } from "./modules/admin/admin.routes.js";
import { reconcileSubmittedPayments } from "./modules/payments/payments.service.js";
import { qrRoutes } from "./modules/qr/qr.routes.js";
import { merchantRoutes } from "./modules/merchant/merchant.routes.js";

// The old schema_migrations ledger is left untouched; this checksummed v5
// tracking migration uses its own ledger and runs before the API starts.
migrateTracking();
migrateWalletFeatures();
migratePaymentAuthorizationIntent();
migrateAccountSettingsExtensions();
migrateWebAuthnPasskeys();
migrateTransactionGasMetadata();

const app = Fastify({
  // Some deployed/local frontend builds still prepend /api. Rewrite before routing
  // so both /qr/pay and /api/qr/pay (and other API routes) reach the same handlers.
  rewriteUrl: (request: import("node:http").IncomingMessage): string => {
    const url = request.url ?? "/";
    return url.startsWith("/api/") ? url.slice(4) : url;
  },
  logger: {
    level: config.LOG_LEVEL,
    transport: isProd ? undefined : { target: "pino-pretty", options: { translateTime: "HH:MM:ss", ignore: "pid,hostname" } },
  },
  trustProxy: isProd,
  bodyLimit: 64 * 1024,
  requestIdHeader: "x-request-id",
});
app.setErrorHandler(errorHandler);
app.setNotFoundHandler(notFoundHandler);

await app.register(helmet, { contentSecurityPolicy: false });
await app.register(cors, { origin: config.CORS_ORIGINS, credentials: true });
await app.register(rateLimit, { max: config.RATE_LIMIT_MAX, timeWindow: config.RATE_LIMIT_WINDOW_SECONDS * 1000 });

app.get("/health", async () => ({ ok: true }));
await app.register(authRoutes);
await app.register(aliasRoutes);
await app.register(ratesRoutes);
await app.register(walletRoutes);
await app.register(paymentRoutes);
await app.register(qrRoutes);
await app.register(withdrawRoutes);
await app.register(contactRoutes);
await app.register(billRoutes);
await app.register(mandateRoutes);
await app.register(bridgeRoutes);
await app.register(assetRoutes);
await app.register(providerRoutes);
await app.register(adminRoutes);
await app.register(merchantRoutes);

const hashMs = await initPassword();
kmsSelfTest();
app.log.info({ hashMs }, "password hasher ready");

const reconcileTimer = setInterval(() => {
  void reconcileSubmittedPayments().catch(() => app.log.warn({ task: "payment_reconciliation" }, "payment reconciliation failed"));
}, 15_000);
reconcileTimer.unref();

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  clearInterval(reconcileTimer);
  await app.close();
  closeDb();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.HOST, port: config.PORT });
app.log.info({ port: config.PORT, chainId: config.MONAD_CHAIN_ID }, "subtle pay api listening");
