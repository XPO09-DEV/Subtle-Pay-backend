import { db } from "../../db.js";
import type { AliasRow } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { badRequest, conflict, notFound } from "../../lib/errors.js";
import { verifyPassword } from "../../lib/password.js";

const ALIAS_RE = /^[a-z0-9_]{3,20}$/;
const RESERVED = new Set(["admin", "support", "subtle", "subtlepay", "monad", "system", "root"]);

export function normalizeAlias(input: string): string {
  return input.trim().toLowerCase().replace(/^@/, "").replace(/@monad$/, "");
}

export function toHandle(aliasOrId: string): string {
  return `${aliasOrId}@monad`;
}

export function claimAlias(userId: string, raw: string, ip?: string): { alias: string } {
  const alias = normalizeAlias(raw);
  if (!ALIAS_RE.test(alias) || RESERVED.has(alias)) {
    throw badRequest("Alias must be 3–20 letters, numbers or underscores");
  }

  const taken = db.prepare("SELECT user_id FROM aliases WHERE alias = ?").get(alias) as
    | { user_id: string }
    | undefined;
  if (taken && taken.user_id !== userId) {
    throw conflict("That name is already taken", "ALIAS_TAKEN");
  }
  const retired = db.prepare("SELECT user_id FROM alias_history WHERE alias = ?").get(alias) as { user_id: string } | undefined;
  if (retired) throw conflict("That handle was previously used and is reserved for its original account", "ALIAS_RESERVED");

  const mine = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
  const now = Date.now();
  if (mine && mine.alias !== alias) throw conflict("Use Settings and confirm your password to change an existing handle", "ALIAS_IMMUTABLE");
  if (!mine) db.prepare("INSERT INTO aliases (alias, user_id, created_at) VALUES (?, ?, ?)").run(alias, userId, now);
  audit(userId, mine ? "alias.claim.reused" : "alias.claim", { alias }, ip);
  return { alias };
}

export async function changeAlias(userId: string, raw: string, currentPassword: string, ip?: string): Promise<{ alias: string; previousAlias: string | null }> {
  const alias = normalizeAlias(raw);
  if (!ALIAS_RE.test(alias) || RESERVED.has(alias)) throw badRequest("Alias must be 3–20 letters, numbers or underscores");
  const user = db.prepare("SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL").get(userId) as { password_hash: string } | undefined;
  if (!user || !(await verifyPassword(user.password_hash, currentPassword))) throw badRequest("Current password is incorrect", "INVALID_CREDENTIALS");
  const active = db.prepare("SELECT user_id FROM aliases WHERE alias = ?").get(alias) as { user_id: string } | undefined;
  if (active && active.user_id !== userId) throw conflict("That name is already taken", "ALIAS_TAKEN");
  const retired = db.prepare("SELECT user_id FROM alias_history WHERE alias = ?").get(alias) as { user_id: string } | undefined;
  if (retired) throw conflict("That handle has been retired and cannot be reassigned", "ALIAS_RESERVED");
  const mine = db.prepare("SELECT alias FROM aliases WHERE user_id = ?").get(userId) as { alias: string } | undefined;
  const previousAlias = mine?.alias ?? null;
  if (previousAlias === alias) return { alias, previousAlias: null };
  db.transaction(() => {
    if (previousAlias) {
      db.prepare("INSERT INTO alias_history (alias, user_id, created_at, replaced_at) VALUES (?, ?, ?, ?)")
        .run(previousAlias, userId, nowForAlias(userId, previousAlias), Date.now());
      db.prepare("UPDATE aliases SET alias = ?, created_at = ? WHERE user_id = ?").run(alias, Date.now(), userId);
    } else {
      db.prepare("INSERT INTO aliases (alias, user_id, created_at) VALUES (?, ?, ?)").run(alias, userId, Date.now());
    }
  })();
  audit(userId, "alias.changed", { previousAlias, alias }, ip);
  return { alias, previousAlias };
}
function nowForAlias(userId: string, alias: string): number {
  const row = db.prepare("SELECT created_at FROM aliases WHERE user_id = ? AND alias = ?").get(userId, alias) as { created_at: number } | undefined;
  return row?.created_at ?? Date.now();
}

export function resolveAlias(name: string): { alias: string; address: string } {
  const alias = normalizeAlias(name);
  const row = db.prepare(
    `SELECT a.alias, w.address FROM aliases a JOIN wallets w ON w.user_id = a.user_id WHERE a.alias = ?
     UNION ALL
     SELECT h.alias, w.address FROM alias_history h JOIN wallets w ON w.user_id = h.user_id WHERE h.alias = ? LIMIT 1`
  ).get(alias, alias) as Pick<AliasRow, "alias"> & { address: string } | undefined;
  if (!row) throw notFound("No account uses that name", "ALIAS_NOT_FOUND");
  return { alias: row.alias, address: row.address };
}