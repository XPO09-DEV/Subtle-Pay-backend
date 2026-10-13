import type { FastifyReply } from "fastify";
import { db } from "../db.js";
import { canonicalJson, sha256Hex } from "../lib/crypto.js";
import { badRequest, conflict } from "../lib/errors.js";

const KEY_RE = /^[A-Za-z0-9_-]{8,128}$/;
/** Same key/body replays saved response; unresolved keys fail closed to avoid duplicate broadcasts. */
export async function runIdempotent(userId: string, key: string | undefined, body: unknown, reply: FastifyReply, run: () => Promise<unknown>): Promise<unknown> {
  if (!key || !KEY_RE.test(key)) throw badRequest("A valid Idempotency-Key header is required for payments", "BAD_REQUEST");
  const requestHash = sha256Hex(canonicalJson(body));
  const existing = db.prepare("SELECT request_hash, status_code, response_body FROM idempotency_keys WHERE user_id = ? AND key = ?")
    .get(userId, key) as { request_hash: string; status_code: number | null; response_body: string | null } | undefined;
  if (existing) {
    if (existing.request_hash !== requestHash) throw conflict("This idempotency key was already used for a different payment", "IDEMPOTENCY_CONFLICT");
    if (existing.response_body && existing.status_code) {
      reply.header("Idempotent-Replayed", "true"); reply.status(existing.status_code);
      return JSON.parse(existing.response_body);
    }
    throw conflict("This payment key has no final response yet. Check transaction history before retrying with a new key.", "IDEMPOTENCY_CONFLICT");
  }
  db.prepare("INSERT INTO idempotency_keys (user_id, key, request_hash, created_at) VALUES (?, ?, ?, ?)")
    .run(userId, key, requestHash, Date.now());
  const result = await run();
  db.prepare("UPDATE idempotency_keys SET status_code = 200, response_body = ? WHERE user_id = ? AND key = ?")
    .run(JSON.stringify(result), userId, key);
  return result;
}
