import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 5;
const NAME = "login_fund_holds_transaction_events";
const SQL = `
  CREATE TABLE login_events (
    id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    subject_hash TEXT NOT NULL CHECK (length(subject_hash) = 64),
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    reason TEXT NOT NULL CHECK (reason IN ('success','invalid_credentials','account_locked','registration')),
    ip TEXT,
    user_agent TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 512),
    request_id TEXT CHECK (request_id IS NULL OR length(request_id) <= 128),
    event_at INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX idx_login_events_account_time ON login_events(account_id, event_at DESC);
  CREATE INDEX idx_login_events_ip_time ON login_events(ip, event_at DESC);
  CREATE INDEX idx_login_events_time_success ON login_events(event_at DESC, success);
  CREATE TABLE fund_holds (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id) ON DELETE RESTRICT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    asset TEXT NOT NULL CHECK (asset IN ('MON','USDC')),
    amount_atomic TEXT NOT NULL CHECK (length(amount_atomic) BETWEEN 1 AND 78 AND amount_atomic NOT GLOB '*[^0-9]*'),
    amount_micro INTEGER NOT NULL CHECK (amount_micro > 0),
    status TEXT NOT NULL CHECK (status IN ('active','released')),
    created_at INTEGER NOT NULL,
    released_at INTEGER,
    release_reason TEXT CHECK (release_reason IS NULL OR release_reason IN ('confirmed','failed','reconciled'))
  ) STRICT;
  CREATE INDEX idx_fund_holds_user_status ON fund_holds(user_id, status, created_at DESC);
  CREATE INDEX idx_fund_holds_status_time ON fund_holds(status, created_at DESC);
  CREATE TABLE transaction_events (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('pending','submitted','confirmed','failed')),
    tx_hash TEXT,
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) <= 64),
    metadata TEXT,
    event_at INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX idx_tx_events_transaction_time ON transaction_events(transaction_id, event_at ASC);
  CREATE INDEX idx_tx_events_time ON transaction_events(event_at DESC);
  CREATE TRIGGER transaction_events_no_update BEFORE UPDATE ON transaction_events
    BEGIN SELECT RAISE(ABORT, 'transaction_events is append-only'); END;
  CREATE TRIGGER transaction_events_no_delete BEFORE DELETE ON transaction_events
    BEGIN SELECT RAISE(ABORT, 'transaction_events is append-only'); END;
  CREATE INDEX idx_tx_created_updated ON transactions(created_at DESC, updated_at DESC);
  CREATE INDEX idx_users_created ON users(created_at DESC);
  CREATE INDEX idx_alias_user_lower ON aliases(user_id, alias);
`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

/**
 * This new numbered ledger is separate from the baseline schema_migrations:
 * the legacy migrator rejects unknown versions, so applied migrations 1-4
 * remain byte-for-byte unchanged and keep their original checksums.
 */
export function migrateTracking(): void {
  db.exec(`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?").get(VERSION)
    as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) throw new Error("Tracking migration 5 checksum mismatch; refusing startup.");
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
