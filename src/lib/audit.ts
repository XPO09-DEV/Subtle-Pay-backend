import { canonicalJson, sha256Hex } from "./crypto.js";
import { db, withTransaction } from "../db.js";

/**
 * Append-only, hash-chained audit row. `details` must never contain secrets.
 * A failure here must not fail the request that triggered it.
 */
export function audit(
  actor: string | null,
  action: string,
  details?: Record<string, unknown>,
  ip?: string
): void {
  try {
    withTransaction(() => {
      const prev = db
        .prepare("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        .get() as { hash: string } | undefined;
      const prevHash = prev?.hash ?? "genesis";
      const ts = Date.now();
      const payload = canonicalJson({
        ts,
        actor,
        action,
        details: details ?? null,
        ip: ip ?? null,
        prevHash,
      });
      db.prepare(
        `INSERT INTO audit_log (ts, actor, action, details, ip, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(
        ts,
        actor,
        action,
        details ? canonicalJson(details) : null,
        ip ?? null,
        prevHash,
        sha256Hex(payload)
      );
    });
  } catch {
    // Do not emit database exceptions here: they can contain implementation details or sensitive values.
    console.error("audit write failed");
  }
}