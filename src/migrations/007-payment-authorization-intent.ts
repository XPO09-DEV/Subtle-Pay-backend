import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 7;
const NAME = "payment_authorization_intent_binding";
const SQL = \`
  ALTER TABLE payment_authorizations
    ADD COLUMN intent_hash TEXT CHECK (intent_hash IS NULL OR length(intent_hash) = 64);
  CREATE INDEX idx_payment_authorization_user_intent
    ON payment_authorizations(user_id, intent_hash, expires_at);
\`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

export function migratePaymentAuthorizationIntent(): void {
  db.exec(\`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;\`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?")
    .get(VERSION) as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) {
      throw new Error("Payment authorization migration 7 checksum mismatch; refusing startup.");
    }
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
