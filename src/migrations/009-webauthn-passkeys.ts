import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 9;
const NAME = "webauthn_passkeys_and_challenges";
const SQL = `
  CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
    transports TEXT NOT NULL DEFAULT '[]',
    device_name TEXT NOT NULL CHECK (length(device_name) BETWEEN 1 AND 60),
    device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice','multiDevice')),
    backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0,1)),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  ) STRICT;
  CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id, created_at DESC);

  CREATE TABLE webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('registration','login','payment')),
    challenge TEXT NOT NULL,
    intent_hash TEXT CHECK (intent_hash IS NULL OR length(intent_hash) = 64),
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at);
  CREATE INDEX idx_webauthn_challenges_user ON webauthn_challenges(user_id, purpose, expires_at);
`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

export function migrateWebAuthnPasskeys(): void {
  db.exec(`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?")
    .get(VERSION) as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) {
      throw new Error("WebAuthn passkey migration 9 checksum mismatch; refusing startup.");
    }
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
