import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 8;
const NAME = "account_country_and_alias_history";
const SQL = `
  ALTER TABLE users ADD COLUMN country TEXT CHECK (country IS NULL OR length(country) = 2);

  CREATE TABLE alias_history (
    alias TEXT PRIMARY KEY CHECK (length(alias) BETWEEN 3 AND 20),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    replaced_at INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX idx_alias_history_user ON alias_history(user_id, replaced_at DESC);
`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

export function migrateAccountSettingsExtensions(): void {
  db.exec(`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?")
    .get(VERSION) as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) {
      throw new Error("Account settings migration 8 checksum mismatch; refusing startup.");
    }
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
