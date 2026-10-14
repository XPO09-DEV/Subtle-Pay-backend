import "dotenv/config";
import { z } from "zod";

const hexBytes = (bytes: number) => z.string().regex(new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`), `must be exactly ${bytes} bytes (${bytes * 2} hex characters)`);
const evmAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/, "must be a 0x-prefixed 20-byte address");
const optionalAddress = z.preprocess((v) => v === "" ? undefined : v, evmAddress.optional());

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),
  CORS_ORIGINS: z.string().default("http://localhost:5174,http://localhost:5173").transform((s) => s.split(",").map((o) => o.trim()).filter(Boolean)),
  WEBAUTHN_RP_NAME: z.string().trim().min(1).max(80).default("Subtle Pay"),
  WEBAUTHN_RP_ID: z.string().trim().min(1).max(253).default("localhost"),
  WEBAUTHN_ORIGIN: z.string().url().default("http://localhost:5174"),
  DB_PATH: z.string().default("./data/subtle.db"),
  ANKR_API_KEY: z.preprocess((v) => typeof v === "string" && v.trim() ? v.trim() : undefined, z.string().min(1).optional()),
  COINSTATS_API_KEY: z.preprocess((v) => typeof v === "string" && v.trim() ? v.trim() : undefined, z.string().min(1).optional()),
  COINSTATS_API_BASE_URL: z.string().url().default("https://openapiv1.coinstats.app"),
  ADMIN_API_TOKEN: z.preprocess((v) => typeof v === "string" && v.trim() ? v.trim() : undefined, z.string().min(32, "must be at least 32 characters").optional()),
  JWT_ACCESS_SECRET: hexBytes(32),
  PASSWORD_PEPPER: hexBytes(32),
  MASTER_KEY: hexBytes(32),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  ARGON2_MEMORY_KIB: z.coerce.number().int().min(19456).default(65536),
  ARGON2_TIME_COST: z.coerce.number().int().min(2).default(3),
  ARGON2_PARALLELISM: z.coerce.number().int().min(1).default(1),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
  LOGIN_MAX_FAILURES: z.coerce.number().int().min(3).default(5),
  LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().min(1).default(15),
  MONAD_RPC_URL: z.string().url(),
  MONAD_CHAIN_ID: z.coerce.number().int().positive(),
  MONAD_EXPLORER_URL: z.string().url().optional(),
  RELAYER_PRIVATE_KEY: z.string().regex(/^0x[0-9a-fA-F]{64}$/, "must be 0x + 64 hex characters"),
  ALIAS_REGISTRY_ADDRESS: optionalAddress,
  PAYMENT_ROUTER_ADDRESS: optionalAddress,
  STABLE_TOKEN_ADDRESS: optionalAddress,
}).superRefine((cfg, ctx) => {
  if (cfg.MONAD_CHAIN_ID !== 10143) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["MONAD_CHAIN_ID"], message: "Subtle Pay hackathon builds are locked to Monad Testnet chain ID 10143" });
  const secrets = {
    JWT_ACCESS_SECRET: cfg.JWT_ACCESS_SECRET.toLowerCase(),
    PASSWORD_PEPPER: cfg.PASSWORD_PEPPER.toLowerCase(),
    MASTER_KEY: cfg.MASTER_KEY.toLowerCase(),
  };
  const seen = new Map<string, string>();
  for (const [name, value] of Object.entries(secrets)) {
    const clash = seen.get(value);
    if (clash) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [name], message: `must differ from ${clash}` });
    seen.set(value, name);
  }
  let webauthnOrigin: URL | null = null;
  try {
    webauthnOrigin = new URL(cfg.WEBAUTHN_ORIGIN);
    if (webauthnOrigin.origin !== cfg.WEBAUTHN_ORIGIN || webauthnOrigin.username || webauthnOrigin.password) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_ORIGIN"], message: "must be an exact origin without a path, query, or credentials" });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_ORIGIN"], message: "must be a valid web origin" });
  }
  if (webauthnOrigin) {
    const host = webauthnOrigin.hostname.toLowerCase();
    const rpId = cfg.WEBAUTHN_RP_ID.toLowerCase();
    if (!(host === rpId || host.endsWith("." + rpId))) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_RP_ID"], message: "must be the frontend origin's hostname or a parent domain" });
    }
    const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1";
    if (cfg.NODE_ENV !== "production" && webauthnOrigin.protocol !== "https:" && !isLocal) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_ORIGIN"], message: "HTTP is allowed only for localhost development; use HTTPS elsewhere" });
    }
    if (cfg.NODE_ENV === "production") {
      if (webauthnOrigin.protocol !== "https:") ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_ORIGIN"], message: "must use HTTPS in production" });
      if (["localhost", "127.0.0.1", "::1"].includes(rpId)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_RP_ID"], message: "must be your real public relying-party domain in production" });
      if (host === "localhost" || host.endsWith(".localhost")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEBAUTHN_ORIGIN"], message: "localhost origin is not allowed in production" });
    }
  }
  if (cfg.NODE_ENV === "production") {
    if (cfg.CORS_ORIGINS.includes("*")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CORS_ORIGINS"], message: "wildcard origin is not allowed in production" });
    const missing = (["ALIAS_REGISTRY_ADDRESS", "PAYMENT_ROUTER_ADDRESS", "STABLE_TOKEN_ADDRESS"] as const).filter((k) => !cfg[k]);
    for (const k of missing) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [k], message: "is required in production" });
    for (const key of ["ANKR_API_KEY", "COINSTATS_API_KEY", "ADMIN_API_TOKEN"] as const) {
      if (!cfg[key]) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: "is required in production; configure it in the server environment, never in source control" });
    }
  }
});
const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`);
  console.error(`Invalid environment configuration:\n${lines.join("\n")}`);
  process.exit(1);
}
export const config = Object.freeze(parsed.data);
export const isProd = config.NODE_ENV === "production";
export type Config = typeof config;
