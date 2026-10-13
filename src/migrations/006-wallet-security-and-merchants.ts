import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 6;
const NAME = "wallet_security_and_merchant_profiles";
const SQL = `
  ALTER TABLE users ADD COLUMN deleted_at INTEGER;

  CREATE TABLE wallet_qr (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    payload TEXT NOT NULL UNIQUE,
    chain_id INTEGER NOT NULL CHECK (chain_id = 10143),
    created_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE pin_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    pin_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE payment_authorizations (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX idx_payment_auth_user_expiry ON payment_authorizations(user_id, expires_at);

  CREATE TABLE merchant_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    public_name TEXT NOT NULL CHECK (length(public_name) BETWEEN 1 AND 80),
    category TEXT NOT NULL DEFAULT 'individual' CHECK (length(category) BETWEEN 1 AND 40),
    status TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','approved','suspended')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    verified_at INTEGER
  ) STRICT;

  CREATE TABLE merchant_autopay_applications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 1000),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER,
    reviewed_by TEXT,
    review_note TEXT CHECK (review_note IS NULL OR length(review_note) <= 500)
  ) STRICT;
  CREATE INDEX idx_merchant_autopay_status_time ON merchant_autopay_applications(status, created_at DESC);
  CREATE UNIQUE INDEX idx_merchant_autopay_one_pending
    ON merchant_autopay_applications(user_id) WHERE status = 'pending';
`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

export function migrateWalletFeatures(): void {
  db.exec(`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?")
    .get(VERSION) as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) {
      throw new Error("Wallet features migration 6 checksum mismatch; refusing startup.");
    }
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
