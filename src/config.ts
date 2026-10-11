import "dotenv/config";
import { z } from "zod";

/** N random bytes written as hex, e.g. 32 bytes = 64 hex characters. */
const hexBytes = (bytes: number) =>
  z
    .string()
    .regex(
      new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`),
      `must be exactly ${bytes} bytes (${bytes * 2} hex characters)`
    );

const evmAddress = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "must be a 0x-prefixed 20-byte address");

const optionalAddress = z.preprocess(
  (v) => (v === "" ? undefined : v),
  evmAddress.optional()
);

const schema = z
  .object({
    // Runtime
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    HOST: z.string().default("0.0.0.0"),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    LOG_LEVEL: z
      .enum(["fatal", "error", "warn", "info", "debug", "trace"])
      .default("info"),
    CORS_ORIGINS: z
      .string()
      .default("http://localhost:5173")
      .transform((s) =>
        s
          .split(",")
          .map((o) => o.trim())
          .filter(Boolean)
      ),

    // Storage
    DB_PATH: z.string().default("./data/subtle.db"),

    // Secrets (each must be distinct; generate with 32 random bytes)
    JWT_ACCESS_SECRET: hexBytes(32),
    PASSWORD_PEPPER: hexBytes(32),
    MASTER_KEY: hexBytes(32), // wraps every per-wallet data key (KMS interface)

    // Sessions
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),

    // Password hashing (argon2id)
    ARGON2_MEMORY_KIB: z.coerce.number().int().min(19456).default(65536),
    ARGON2_TIME_COST: z.coerce.number().int().min(2).default(3),
    ARGON2_PARALLELISM: z.coerce.number().int().min(1).default(1),

    // Abuse protection
    RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
    RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
    LOGIN_MAX_FAILURES: z.coerce.number().int().min(3).default(5),
    LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().min(1).default(15),

    // Monad
    MONAD_RPC_URL: z.string().url(),
    MONAD_CHAIN_ID: z.coerce.number().int().positive(),
    MONAD_EXPLORER_URL: z.string().url().optional(),
    RELAYER_PRIVATE_KEY: z
      .string()
      .regex(/^0x[0-9a-fA-F]{64}$/, "must be 0x + 64 hex characters"),

    // Contract addresses (filled in after deployment)
    ALIAS_REGISTRY_ADDRESS: optionalAddress,
    PAYMENT_ROUTER_ADDRESS: optionalAddress,
    STABLE_TOKEN_ADDRESS: optionalAddress,
  })
  .superRefine((cfg, ctx) => {
    // Reusing one secret for several purposes defeats the point of having several.
    const secrets = {
      JWT_ACCESS_SECRET: cfg.JWT_ACCESS_SECRET.toLowerCase(),
      PASSWORD_PEPPER: cfg.PASSWORD_PEPPER.toLowerCase(),
      MASTER_KEY: cfg.MASTER_KEY.toLowerCase(),
    };
    const seen = new Map<string, string>();
    for (const [name, value] of Object.entries(secrets)) {
      const clash = seen.get(value);
      if (clash) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [name],
          message: `must differ from ${clash}`,
        });
      }
      seen.set(value, name);
    }

    if (cfg.NODE_ENV === "production") {
      if (cfg.CORS_ORIGINS.includes("*")) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["CORS_ORIGINS"],
          message: "wildcard origin is not allowed in production",
        });
      }
      const missing = (
        ["ALIAS_REGISTRY_ADDRESS", "PAYMENT_ROUTER_ADDRESS", "STABLE_TOKEN_ADDRESS"] as const
      ).filter((k) => !cfg[k]);
      for (const k of missing) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [k],
          message: "is required in production",
        });
      }
    }
  });

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  const lines = parsed.error.issues.map(
    (i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`
  );
  // Print names and reasons only, never the values (they may be secrets).
  console.error(`Invalid environment configuration:\n${lines.join("\n")}`);
  process.exit(1);
}

export const config = Object.freeze(parsed.data);
export const isProd = config.NODE_ENV === "production";
export type Config = typeof config;