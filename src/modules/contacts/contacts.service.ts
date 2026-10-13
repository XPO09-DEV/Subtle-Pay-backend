import { isAddress } from "viem";
import { db } from "../../db.js";
import { isValidAccountId, newId, normalizeAccountId } from "../../lib/crypto.js";
import { normalizeAlias } from "../alias/alias.service.js";
import { badRequest, conflict, notFound } from "../../lib/errors.js";
import { audit } from "../../lib/audit.js";

const NAME_RE = /^[a-z0-9][a-z0-9 _.-]{0,30}$/;
export function normalizeContactName(input: string): string { return input.trim().toLowerCase().replace(/\s+/g, " "); }

export function saveContact(ownerId: string, rawName: string, target: { accountId?: string; address?: string; alias?: string }, ip?: string) {
  const name = normalizeContactName(rawName);
  if (!NAME_RE.test(name)) throw badRequest("Name must be 1–32 letters, numbers, spaces, . _ or -");
  let accountId: string | null = null;
  let address: string | null = null;
  if (target.accountId) {
    accountId = normalizeAccountId(target.accountId);
    if (!isValidAccountId(accountId)) throw badRequest("That account id is not valid", "INVALID_ACCOUNT_ID");
    if (!db.prepare("SELECT 1 FROM users WHERE id = ?").get(accountId)) throw notFound("No account uses that id");
  } else if (target.address && isAddress(target.address)) {
    address = target.address;
  } else if (target.alias) {
    const alias = normalizeAlias(target.alias);
    const row = db.prepare("SELECT user_id FROM aliases WHERE alias = ?").get(alias) as { user_id: string } | undefined;
    if (!row) throw notFound("No account uses that handle", "ALIAS_NOT_FOUND");
    accountId = row.user_id;
  } else throw badRequest("Give a Subtle Pay handle, account id or wallet address");

  const now = Date.now();
  const existing = db.prepare("SELECT id FROM contacts WHERE owner_id = ? AND name = ?").get(ownerId, name) as { id: string } | undefined;
  if (existing) db.prepare("UPDATE contacts SET account_id = ?, address = ? WHERE id = ?").run(accountId, address, existing.id);
  else {
    try {
      db.prepare("INSERT INTO contacts (id, owner_id, name, account_id, address, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .run(newId(), ownerId, name, accountId, address, now);
    } catch { throw conflict("You already saved that name"); }
  }
  audit(ownerId, "contact.save", { name }, ip);
  return { name, accountId, address };
}
export function listContacts(ownerId: string) {
  return db.prepare("SELECT name, account_id AS accountId, address, created_at AS createdAt FROM contacts WHERE owner_id = ? ORDER BY name").all(ownerId);
}
export function deleteContact(ownerId: string, rawName: string) {
  const name = normalizeContactName(rawName);
  const result = db.prepare("DELETE FROM contacts WHERE owner_id = ? AND name = ?").run(ownerId, name);
  if (result.changes === 0) throw notFound("No contact uses that name");
  return { ok: true };
}
/** Private label for this user only. Null if they have not saved that name. */
export function findContact(ownerId: string, rawName: string): { accountId: string | null; address: string | null } | null {
  const name = normalizeContactName(rawName);
  return (db.prepare("SELECT account_id AS accountId, address FROM contacts WHERE owner_id = ? AND name = ?").get(ownerId, name) as { accountId: string | null; address: string | null } | undefined) ?? null;
}
