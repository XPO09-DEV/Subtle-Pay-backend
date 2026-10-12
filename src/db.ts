import Database from "better-sqlite3";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

/* -------------------------------------------------------------------------- */
/*  Connection                                                                */
/* -------------------------------------------------------------------------- */

const dbPath = path.resolve(config.DB_PATH);
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

export const db: Database.Database = new Database(dbPath);

// Owner-only permissions on the database file (best effort; no-op on Windows).
try {
  fs.chmodSync(dbPath, 0o600);
} catch {
  /* ignore */
}

db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");
db.pragma("secure_delete = ON"); // overwrite deleted content with zeros
db.pragma("trusted_schema = OFF");

/* -------------------------------------------------------------------------- */
/*  Migrations                                                                */
/* -------------------------------------------------------------------------- */

interface Migration {
  version: number;
  name: string;
  sql: string;
}

/**
 * Rules:
 *  - Never edit a migration that has been applied. Add a new one instead.
 *    (A checksum guard refuses to start if an applied migration changed.)
 *  - Money is always an INTEGER in micro-units (1 USD = 1_000_000).
 *  - Timestamps are unix epoch milliseconds (INTEGER).
 */
const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: "core_schema",
    sql: `
      CREATE TABLE users (
        id              TEXT PRIMARY KEY CHECK (length(id) = 27),
        password_hash   TEXT NOT NULL,
        currency        TEXT NOT NULL DEFAULT 'USD' CHECK (length(currency) = 3),
        failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
        locked_until    INTEGER,
        created_at      INTEGER NOT NULL,
        updated_at      INTEGER NOT NULL
      ) STRICT;

      -- One custodial wallet per user. The private key is NEVER stored in plain
      -- text: enc_priv_key holds an envelope-encrypted blob (per-wallet data key,
      -- wrapped by the master key). kek_version allows master key rotation.
      CREATE TABLE wallets (
        user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
        address      TEXT NOT NULL UNIQUE CHECK (address GLOB '0x[0-9a-fA-F]*' AND length(address) = 42),
        enc_priv_key TEXT NOT NULL,
        kek_version  INTEGER NOT NULL DEFAULT 1,
        created_at   INTEGER NOT NULL
      ) STRICT;

      -- Stored lowercase; 3-20 chars of a-z, 0-9, underscore. Display casing
      -- ("ANI") is a frontend concern.
      CREATE TABLE aliases (
        alias      TEXT PRIMARY KEY
                   CHECK (length(alias) BETWEEN 3 AND 20
                          AND alias = lower(alias)
                          AND alias NOT GLOB '*[^a-z0-9_]*'),
        user_id    TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
        tx_hash    TEXT,                -- on-chain registration (AliasRegistry)
        created_at INTEGER NOT NULL
      ) STRICT;

      -- Refresh tokens are stored as SHA-256 hashes only. A "family" is one login
      -- session; if a rotated token is ever reused, the whole family is revoked.
      CREATE TABLE refresh_tokens (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        family_id   TEXT NOT NULL,
        token_hash  TEXT NOT NULL UNIQUE,
        expires_at  INTEGER NOT NULL,
        used_at     INTEGER,
        revoked_at  INTEGER,
        replaced_by TEXT,
        ip          TEXT,
        user_agent  TEXT,
        created_at  INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX idx_refresh_user   ON refresh_tokens(user_id);
      CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
      CREATE INDEX idx_refresh_expiry ON refresh_tokens(expires_at);

      -- Payments move a USD-pegged token (6 decimals), so amount_micro IS the
      -- dollar value. The display-currency rate is frozen at send time.
      CREATE TABLE transactions (
        id               TEXT PRIMARY KEY,
        from_user        TEXT NOT NULL REFERENCES users(id),
        to_user          TEXT REFERENCES users(id),     -- null if external address
        from_address     TEXT NOT NULL,
        to_address       TEXT NOT NULL,
        amount_micro     INTEGER NOT NULL CHECK (amount_micro > 0),
        display_currency TEXT NOT NULL,
        fx_rate          REAL NOT NULL CHECK (fx_rate > 0), -- 1 USD = fx_rate display_currency
        status           TEXT NOT NULL
                         CHECK (status IN ('pending','submitted','confirmed','failed')),
        tx_hash          TEXT UNIQUE,
        failure_reason   TEXT,
        note             TEXT CHECK (note IS NULL OR length(note) <= 140),
        created_at       INTEGER NOT NULL,
        updated_at       INTEGER NOT NULL,
        confirmed_at     INTEGER,
        CHECK (from_address <> to_address)
      ) STRICT;
      CREATE INDEX idx_tx_from   ON transactions(from_user, created_at DESC);
      CREATE INDEX idx_tx_to     ON transactions(to_user, created_at DESC);
      CREATE INDEX idx_tx_status ON transactions(status);

      -- Mocked cash-out for the prototype; the shape is production-ready.
      CREATE TABLE withdrawals (
        id                  TEXT PRIMARY KEY,
        user_id             TEXT NOT NULL REFERENCES users(id),
        amount_micro        INTEGER NOT NULL CHECK (amount_micro > 0),
        currency            TEXT NOT NULL,
        fx_rate             REAL NOT NULL CHECK (fx_rate > 0),
        payout_minor_units  INTEGER NOT NULL CHECK (payout_minor_units >= 0),
        status              TEXT NOT NULL
                            CHECK (status IN ('pending','processing','completed','failed')),
        created_at          INTEGER NOT NULL,
        updated_at          INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX idx_withdrawals_user ON withdrawals(user_id, created_at DESC);

      -- Idempotency: the same key + same body replays the stored response;
      -- the same key + different body is rejected. Prevents double payments.
      CREATE TABLE idempotency_keys (
        user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        key           TEXT NOT NULL CHECK (length(key) BETWEEN 8 AND 128),
        request_hash  TEXT NOT NULL,
        status_code   INTEGER,
        response_body TEXT,
        created_at    INTEGER NOT NULL,
        PRIMARY KEY (user_id, key)
      ) STRICT;
      CREATE INDEX idx_idem_created ON idempotency_keys(created_at);

      -- Tamper-evident audit trail: each row stores the hash of the previous row.
      -- Triggers make the table append-only at the database level.
      CREATE TABLE audit_log (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         INTEGER NOT NULL,
        actor      TEXT,                 -- user id, or 'system'
        action     TEXT NOT NULL,
        details    TEXT,                 -- JSON, never contains secrets
        ip         TEXT,
        prev_hash  TEXT NOT NULL,
        hash       TEXT NOT NULL UNIQUE
      );
      CREATE INDEX idx_audit_actor ON audit_log(actor, ts DESC);

      CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

      CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    `,
  },

  {
    version: 2,
    name: "contacts",
    sql: `
      CREATE TABLE contacts (
        id         TEXT PRIMARY KEY,
        owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 32),
        account_id TEXT REFERENCES users(id),
        address    TEXT,
        created_at INTEGER NOT NULL,
        UNIQUE (owner_id, name),
        CHECK ((account_id IS NOT NULL AND address IS NULL) OR (account_id IS NULL AND address IS NOT NULL))
      ) STRICT;
      CREATE INDEX idx_contacts_owner ON contacts(owner_id, name);
    `,
  },

  {
    version: 3,
    name: "bills_and_mandates",
    sql: `
      CREATE TABLE bills (
        id           TEXT PRIMARY KEY,
        merchant_id  TEXT NOT NULL REFERENCES users(id),
        amount_text  TEXT NOT NULL,
        currency     TEXT NOT NULL,
        note         TEXT,
        status       TEXT NOT NULL CHECK (status IN ('open','paid','expired','cancelled')),
        payer_id     TEXT REFERENCES users(id),
        tx_id        TEXT,
        expires_at   INTEGER NOT NULL,
        created_at   INTEGER NOT NULL,
        paid_at      INTEGER
      ) STRICT;
      CREATE INDEX idx_bills_merchant ON bills(merchant_id, created_at);

      CREATE TABLE mandates (
        id            TEXT PRIMARY KEY,
        user_id       TEXT NOT NULL REFERENCES users(id),
        merchant_id   TEXT NOT NULL REFERENCES users(id),
        cap_micro     INTEGER NOT NULL CHECK (cap_micro > 0),
        currency      TEXT NOT NULL,
        interval_days INTEGER NOT NULL CHECK (interval_days BETWEEN 1 AND 365),
        status        TEXT NOT NULL CHECK (status IN ('active','paused','revoked')),
        created_at    INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX idx_mandates_user ON mandates(user_id, created_at);
    `,
  },
  {
    version: 4,
    name: "consented_user_profile",
    sql: `
      ALTER TABLE users ADD COLUMN display_name TEXT
        CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 80);
      ALTER TABLE users ADD COLUMN region TEXT
        CHECK (region IS NULL OR length(region) BETWEEN 1 AND 80);
      ALTER TABLE users ADD COLUMN region_consent_at INTEGER;
    `,
  },
];

const checksum = (sql: string) =>
  crypto.createHash("sha256").update(sql).digest("hex");

export function migrate(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      checksum   TEXT NOT NULL,
      applied_at INTEGER NOT NULL
    ) STRICT;
  `);

  const applied = new Map<number, { name: string; checksum: string }>(
    (
      db
        .prepare("SELECT version, name, checksum FROM schema_migrations")
        .all() as { version: number; name: string; checksum: string }[]
    ).map((r) => [r.version, r])
  );

  // Refuse to run if history was altered or a migration is missing.
  for (const m of MIGRATIONS) {
    const prev = applied.get(m.version);
    if (prev && prev.checksum !== checksum(m.sql)) {
      throw new Error(
        `Migration ${m.version} (${m.name}) was modified after being applied. ` +
          `Add a new migration instead of editing an old one.`
      );
    }
  }
  const known = new Set(MIGRATIONS.map((m) => m.version));
  for (const v of applied.keys()) {
    if (!known.has(v)) {
      throw new Error(
        `Database has migration ${v} which this code does not know about. ` +
          `Is the database from a newer version?`
      );
    }
  }

  const insert = db.prepare(
    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)"
  );

  for (const m of [...MIGRATIONS].sort((a, b) => a.version - b.version)) {
    if (applied.has(m.version)) continue;
    // Each migration runs atomically: all of it, or none of it.
    db.transaction(() => {
      db.exec(m.sql);
      insert.run(m.version, m.name, checksum(m.sql), Date.now());
    })();
  }
}

migrate();

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Run `fn` in a write transaction that takes the write lock up front (IMMEDIATE),
 * so read-then-write sequences such as "check balance, then record payment"
 * cannot interleave with another writer.
 */
export function withTransaction<T>(fn: () => T): T {
  return db.transaction(fn).immediate();
}

/** Close cleanly on shutdown (flushes the WAL). */
export function closeDb(): void {
  if (db.open) {
    db.pragma("wal_checkpoint(TRUNCATE)");
    db.close();
  }
}

/* -------------------------------------------------------------------------- */
/*  Row types (kept next to the schema so they cannot drift apart)            */
/* -------------------------------------------------------------------------- */

export interface UserRow {
  id: string;
  password_hash: string;
  currency: string;
  failed_attempts: number;
  locked_until: number | null;
  created_at: number;
  updated_at: number;
  display_name: string | null;
  region: string | null;
  region_consent_at: number | null;
}

export interface WalletRow {
  user_id: string;
  address: string;
  enc_priv_key: string;
  kek_version: number;
  created_at: number;
}

export interface AliasRow {
  alias: string;
  user_id: string;
  tx_hash: string | null;
  created_at: number;
}

export interface RefreshTokenRow {
  id: string;
  user_id: string;
  family_id: string;
  token_hash: string;
  expires_at: number;
  used_at: number | null;
  revoked_at: number | null;
  replaced_by: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: number;
}

export type TxStatus = "pending" | "submitted" | "confirmed" | "failed";

export interface TransactionRow {
  id: string;
  from_user: string;
  to_user: string | null;
  from_address: string;
  to_address: string;
  amount_micro: number;
  display_currency: string;
  fx_rate: number;
  status: TxStatus;
  tx_hash: string | null;
  failure_reason: string | null;
  note: string | null;
  created_at: number;
  updated_at: number;
  confirmed_at: number | null;
}

export type WithdrawalStatus = "pending" | "processing" | "completed" | "failed";

export interface WithdrawalRow {
  id: string;
  user_id: string;
  amount_micro: number;
  currency: string;
  fx_rate: number;
  payout_minor_units: number;
  status: WithdrawalStatus;
  created_at: number;
  updated_at: number;
}