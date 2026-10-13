import { canonicalJson, sha256Hex } from "./crypto.js";
import { db, withTransaction } from "../db.js";

/** Append-only, hash-chained audit row. Details must never contain secrets. */
export function audit(actor: string | null, action: string, details?: Record<string, unknown>, ip?: string): void {
  try {
    withTransaction(() => {
      const prev = db.prepare("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").get() as { hash: string } | undefined;
      const prevHash = prev?.hash ?? "genesis";
      const ts = Date.now();
      const payload = canonicalJson({ ts, actor, action, details: details ?? null, ip: ip ?? null, prevHash });
      db.prepare("INSERT INTO audit_log (ts, actor, action, details, ip, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(ts, actor, action, details ? canonicalJson(details) : null, ip ?? null, prevHash, sha256Hex(payload));
    });
  } catch {
    console.error("audit write failed");
  }
}
