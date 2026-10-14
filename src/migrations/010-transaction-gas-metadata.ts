import crypto from "node:crypto";
import { db } from "../db.js";

const VERSION = 10;
const NAME = "transaction_gas_metadata";
const SQL = `
  ALTER TABLE transactions ADD COLUMN asset TEXT NOT NULL DEFAULT 'MON' CHECK (asset IN ('MON','USDC'));
  ALTER TABLE transactions ADD COLUMN gas_used TEXT;
  ALTER TABLE transactions ADD COLUMN effective_gas_price_wei TEXT;
  ALTER TABLE transactions ADD COLUMN fee_paid_wei TEXT;
`;
const checksum = crypto.createHash("sha256").update(SQL).digest("hex");

/** Gas usage is persisted beside the payment so receipts and history survive reloads. */
export function migrateTransactionGasMetadata(): void {
  db.exec(`CREATE TABLE IF NOT EXISTS integration_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL
  ) STRICT;`);
  const applied = db.prepare("SELECT name, checksum FROM integration_migrations WHERE version = ?")
    .get(VERSION) as { name: string; checksum: string } | undefined;
  if (applied) {
    if (applied.name !== NAME || applied.checksum !== checksum) {
      throw new Error("Transaction gas metadata migration 10 checksum mismatch; refusing startup.");
    }
    return;
  }
  db.transaction(() => {
    db.exec(SQL);
    db.prepare("INSERT INTO integration_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")
      .run(VERSION, NAME, checksum, Date.now());
  })();
}
