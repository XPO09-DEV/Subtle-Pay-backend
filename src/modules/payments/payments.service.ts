import { isAddress } from "viem";
import { config } from "../../config.js";
import { formatMon, formatToken, getNativeBalance, getTokenBalance, getReceiptStatus, sendNative, sendToken, waitConfirmed } from "../../chain/monad.js";
import { db, withTransaction, type TransactionRow } from "../../db.js";
import { canonicalJson, newId } from "../../lib/crypto.js";
import { assertPaymentWithinLimits, localMinorToUsdMicro, microToDecimalString, minorToDecimalString, parseAmountMinor, parseUsdToMicro, usdMicroToLocalMinor, type Currency } from "../../lib/currency.js";
import { badRequest, insufficientFunds, notFound, unprocessable } from "../../lib/errors.js";
import { withDecryptedSecret } from "../../lib/kms.js";
import { audit } from "../../lib/audit.js";
import { normalizeAlias } from "../alias/alias.service.js";
import { getRates } from "../rates/rates.service.js";
import { getWalletRow, invalidateWalletView } from "../wallet/wallet.service.js";
import { findContact } from "../contacts/contacts.service.js";

const locks = new Map<string, Promise<unknown>>();
async function exclusive<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(userId) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  locks.set(userId, run.then(() => undefined, () => undefined));
  return run;
}
function parseAmount(amount: string | number, currency: Currency): number {
  const text = typeof amount === "number" ? String(amount) : amount.trim();
  return currency === "USD" ? parseUsdToMicro(text) : parseAmountMinor(text, currency);
}

export async function sendPayment(userId: string, input: { to: string; amount: string | number; amountCurrency: string; note?: string; asset?: string }, ip?: string) {
  return exclusive(userId, async () => {
    const requestedAsset = (input.asset ?? "MON").trim().toUpperCase();
    if (requestedAsset !== "MON") throw unprocessable("Hackathon payments are restricted to native MON on Monad Testnet. Other displayed assets are not transferable in this build.", "CHAIN_UNAVAILABLE");
    if (config.MONAD_CHAIN_ID !== 10143) throw unprocessable("Native MON payments are locked to Monad Testnet (chain ID 10143) for this hackathon build.", "CHAIN_UNAVAILABLE");
    const currency = input.amountCurrency.trim().toUpperCase() as Currency;
    const displayMinorOrMicro = parseAmount(input.amount, currency);
    const rates = await getRates(currency);
    const usdMicro = currency === "USD" ? displayMinorOrMicro : localMinorToUsdMicro(displayMinorOrMicro, rates.usdLocal, currency);
    assertPaymentWithinLimits(usdMicro);
    if (input.note && input.note.length > 140) throw badRequest("Note is too long");
    const from = getWalletRow(userId);
    const dest = await resolveDestination(input.to, userId);
    if (dest.address.toLowerCase() === from.address.toLowerCase()) throw unprocessable("You cannot pay yourself", "SELF_PAYMENT");
    // Native-only settlement for this hackathon, even if an optional token is configured.
    const stable = false;
    const tokenBase = stable ? BigInt(usdMicro) : monWei(usdMicro, rates.tokenUsd);
    if (tokenBase <= 0n) throw badRequest("Amount is too small", "INVALID_AMOUNT");
    const balance = stable ? await getTokenBalance(from.address as `0x${string}`) : await getNativeBalance(from.address as `0x${string}`);
    if (balance === null) throw insufficientFunds();

    const txId = newId();
    const now = Date.now();
    withTransaction(() => {
      const active = db.prepare("SELECT amount_atomic FROM fund_holds WHERE user_id = ? AND asset = 'MON' AND status = 'active'")
        .all(userId) as Array<{ amount_atomic: string }>;
      const reserved = active.reduce((total, row) => total + BigInt(row.amount_atomic), 0n);
      if (balance < reserved + tokenBase) throw insufficientFunds();
      db.prepare(`INSERT INTO transactions
        (id, from_user, to_user, from_address, to_address, amount_micro, display_currency, fx_rate, status, note, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`)
        .run(txId, userId, dest.userId, from.address, dest.address, usdMicro, currency, rates.usdLocal, input.note ?? null, now, now);
      db.prepare(`INSERT INTO fund_holds (id, transaction_id, user_id, asset, amount_atomic, amount_micro, status, created_at)
        VALUES (?, ?, ?, 'MON', ?, ?, 'active', ?)`)
        .run(newId(), txId, userId, tokenBase.toString(), usdMicro, now);
      db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, metadata, event_at) VALUES (?, ?, 'pending', ?, ?)`)
        .run(newId(), txId, canonicalJson({ asset: "MON", amountMicro: usdMicro }), now);
    });
    audit(userId, "payment.hold_created", { txId, asset: "MON", amountMicro: usdMicro }, ip);
    invalidateWalletView(userId);

    let submittedHash: `0x${string}` | null = null;
    try {
      submittedHash = await withDecryptedSecret(from.enc_priv_key, { userId, address: from.address }, async (secret) => {
        const key = `0x${secret.toString("hex")}` as `0x${string}`;
        return stable ? sendToken(key, dest.address as `0x${string}`, tokenBase) : sendNative(key, dest.address as `0x${string}`, tokenBase);
      });
      const submittedAt = Date.now();
      withTransaction(() => {
        db.prepare("UPDATE transactions SET status = 'submitted', tx_hash = ?, updated_at = ? WHERE id = ?").run(submittedHash, submittedAt, txId);
        db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, tx_hash, event_at) VALUES (?, ?, 'submitted', ?, ?)`)
          .run(newId(), txId, submittedHash, submittedAt);
      });
      audit(userId, "payment.submitted", { txId, txHash: submittedHash }, ip);
      const observedStatus = await waitConfirmed(submittedHash);
      const finalizedAt = Date.now();
      withTransaction(() => {
        db.prepare("UPDATE transactions SET status = ?, failure_reason = ?, updated_at = ?, confirmed_at = ? WHERE id = ?")
          .run(observedStatus, observedStatus === "failed" ? "chain_reverted" : null, finalizedAt, observedStatus === "confirmed" ? finalizedAt : null, txId);
        if (observedStatus === "confirmed" || observedStatus === "failed") {
          db.prepare("UPDATE fund_holds SET status = 'released', released_at = ?, release_reason = ? WHERE transaction_id = ? AND status = 'active'")
            .run(finalizedAt, observedStatus, txId);
        }
        db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, tx_hash, failure_code, event_at) VALUES (?, ?, ?, ?, ?, ?)`)
          .run(newId(), txId, observedStatus, submittedHash, observedStatus === "failed" ? "CHAIN_REVERTED" : null, finalizedAt);
      });
      invalidateWalletView(userId);
      audit(userId, observedStatus === "confirmed" ? "payment.confirmed" : observedStatus === "failed" ? "payment.failed" : "payment.confirmation_pending", { txId, status: observedStatus }, ip);
      if (observedStatus === "confirmed" || observedStatus === "failed") audit(userId, "payment.hold_released", { txId, reason: observedStatus }, ip);
      audit(userId, "payment.send", { txId, status: observedStatus, usdMicro }, ip);
      return { txId, status: observedStatus, tokenAmount: stable ? formatToken(tokenBase, 6) : formatMon(tokenBase), usdValue: microToDecimalString(usdMicro), txHash: submittedHash };
    } catch (err) {
      const failedAt = Date.now();
      if (submittedHash) {
        // Once a chain hash exists, a transient receipt/RPC issue is not proof of failure.
        withTransaction(() => {
          db.prepare("UPDATE transactions SET status = 'submitted', tx_hash = ?, updated_at = ? WHERE id = ? AND status != 'confirmed'").run(submittedHash, failedAt, txId);
          db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, tx_hash, failure_code, metadata, event_at)
            VALUES (?, ?, 'submitted', ?, 'CONFIRMATION_PENDING', ?, ?)`)
            .run(newId(), txId, submittedHash, canonicalJson({ reason: "receipt_unavailable" }), failedAt);
        });
        invalidateWalletView(userId);
        audit(userId, "payment.confirmation_pending", { txId }, ip);
        return { txId, status: "submitted" as const, tokenAmount: stable ? formatToken(tokenBase, 6) : formatMon(tokenBase), usdValue: microToDecimalString(usdMicro), txHash: submittedHash };
      }
      withTransaction(() => {
        db.prepare("UPDATE transactions SET status = 'failed', failure_reason = ?, updated_at = ? WHERE id = ?").run("chain_submission_failed", failedAt, txId);
        db.prepare("UPDATE fund_holds SET status = 'released', released_at = ?, release_reason = 'failed' WHERE transaction_id = ? AND status = 'active'").run(failedAt, txId);
        db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, tx_hash, failure_code, event_at) VALUES (?, ?, 'failed', NULL, 'CHAIN_SUBMISSION_FAILED', ?)`)
          .run(newId(), txId, failedAt);
      });
      invalidateWalletView(userId);
      audit(userId, "payment.failed", { txId, stage: "submission" }, ip);
      audit(userId, "payment.hold_released", { txId, reason: "failed" }, ip);
      throw err;
    }
  });
}

function monWei(usdMicro: number, tokenUsd: number): bigint {
  if (!Number.isFinite(tokenUsd) || tokenUsd <= 0) throw badRequest("No MON price", "RATES_UNAVAILABLE");
  const mon = usdMicro / 1_000_000 / tokenUsd;
  return BigInt(Math.round(mon * 1e18));
}
async function resolveDestination(to: string, ownerId?: string): Promise<{ address: string; userId: string | null }> {
  const raw = to.trim();
  if (ownerId) {
    const saved = findContact(ownerId, raw);
    if (saved?.accountId) return resolveDestination(saved.accountId);
    if (saved?.address) return resolveDestination(saved.address);
  }
  if (raw.length === 27) {
    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(raw.toUpperCase()) as { id: string } | undefined;
    if (user) {
      const wallet = db.prepare("SELECT address FROM wallets WHERE user_id = ?").get(user.id) as { address: string };
      return { address: wallet.address, userId: user.id };
    }
  }
  if (isAddress(raw)) {
    const row = db.prepare("SELECT user_id, address FROM wallets WHERE lower(address) = lower(?)").get(raw) as { user_id: string; address: string } | undefined;
    return { address: row?.address ?? raw, userId: row?.user_id ?? null };
  }
  const alias = normalizeAlias(raw);
  const row = db.prepare(`SELECT a.user_id, w.address FROM aliases a JOIN wallets w ON w.user_id = a.user_id WHERE a.alias = ?`).get(alias) as { user_id: string; address: string } | undefined;
  if (!row) throw notFound("No account uses that name", "ALIAS_NOT_FOUND");
  return { address: row.address, userId: row.user_id };
}
export function listPayments(userId: string, options: {
  limit?: number; before?: number; beforeId?: string; q?: string;
  status?: "pending" | "submitted" | "confirmed" | "failed";
  direction?: "in" | "out";
} = {}) {
  const limit = Math.min(100, Math.max(1, Math.trunc(options.limit ?? 50)));
  const where = ["(t.from_user = ? OR t.to_user = ?)"];
  const args: Array<string | number> = [userId, userId];
  if (options.q?.trim()) {
    const needle = `%${options.q.trim().toLowerCase().replace(/[\\%_]/g, "\\export function listPayments(userId: string, options: { limit?: number; before?: number; beforeId?: string } = {}) {
  const user = db.prepare("SELECT currency FROM users WHERE id = ?").get(userId) as { currency: Currency };
  const limit = Math.min(100, Math.max(1, Math.trunc(options.limit ?? 50)));
  const before = options.before, beforeId = options.beforeId;
  const rows = db.prepare(`SELECT t.*, fa.alias AS from_alias, ta.alias AS to_alias
    FROM transactions t LEFT JOIN aliases fa ON fa.user_id = t.from_user LEFT JOIN aliases ta ON ta.user_id = t.to_user
    WHERE (t.from_user = ? OR t.to_user = ?) AND (? IS NULL OR t.created_at < ? OR (t.created_at = ? AND ? IS NOT NULL AND t.id < ?))
    ORDER BY t.created_at DESC, t.id DESC LIMIT ?`)
    .all(userId, userId, before ?? null, before ?? null, before ?? null, beforeId ?? null, beforeId ?? "", limit) as Array<TransactionRow & { from_alias: string | null; to_alias: string | null }>;
  return rows.map((row) => {
    const outgoing = row.from_user === userId;
    const localMinor = usdMicroToLocalMinor(row.amount_micro, row.fx_rate, row.display_currency as Currency);
    return {
      id: row.id, direction: outgoing ? "out" : "in",
      counterparty: outgoing ? row.to_alias ?? row.to_address : row.from_alias ?? row.from_address,
      usdValue: microToDecimalString(row.amount_micro), localValue: minorToDecimalString(localMinor, row.display_currency as Currency),
      displayCurrency: row.display_currency, status: row.status, txHash: row.tx_hash,
      confirmedAt: row.confirmed_at, updatedAt: row.updated_at, createdAt: new Date(row.created_at).toISOString(),
    };
  });
}")}%`;
    where.push(`(
      lower(t.id) LIKE ? ESCAPE '\\' OR lower(COALESCE(t.tx_hash, '')) LIKE ? ESCAPE '\\'
      OR lower(COALESCE(t.note, '')) LIKE ? ESCAPE '\\'
      OR lower(COALESCE(fa.alias, '')) LIKE ? ESCAPE '\\'
      OR lower(COALESCE(ta.alias, '')) LIKE ? ESCAPE '\\'
      OR lower(t.from_address) LIKE ? ESCAPE '\\' OR lower(t.to_address) LIKE ? ESCAPE '\\'
    )`);
    args.push(needle, needle, needle, needle, needle, needle, needle);
  }
  if (options.status) { where.push("t.status = ?"); args.push(options.status); }
  if (options.direction === "out") { where.push("t.from_user = ?"); args.push(userId); }
  if (options.direction === "in") { where.push("t.to_user = ?"); args.push(userId); }
  if (options.before !== undefined) {
    if (options.beforeId) { where.push("(t.created_at < ? OR (t.created_at = ? AND t.id < ?))"); args.push(options.before, options.before, options.beforeId); }
    else { where.push("t.created_at < ?"); args.push(options.before); }
  }
  const rows = db.prepare(`SELECT t.*, fa.alias AS from_alias, ta.alias AS to_alias
    FROM transactions t LEFT JOIN aliases fa ON fa.user_id = t.from_user LEFT JOIN aliases ta ON ta.user_id = t.to_user
    WHERE ${where.join(" AND ")}
    ORDER BY t.created_at DESC, t.id DESC LIMIT ?`)
    .all(...args, limit) as Array<TransactionRow & { from_alias: string | null; to_alias: string | null }>;
  return rows.map((row) => {
    const outgoing = row.from_user === userId;
    const localMinor = usdMicroToLocalMinor(row.amount_micro, row.fx_rate, row.display_currency as Currency);
    return {
      id: row.id, direction: outgoing ? "out" : "in",
      counterparty: outgoing ? row.to_alias ?? row.to_address : row.from_alias ?? row.from_address,
      usdValue: microToDecimalString(row.amount_micro), localValue: minorToDecimalString(localMinor, row.display_currency as Currency),
      displayCurrency: row.display_currency, status: row.status, txHash: row.tx_hash, note: row.note,
      confirmedAt: row.confirmed_at, updatedAt: row.updated_at, createdAt: new Date(row.created_at).toISOString(),
    };
  });
}
export { withTransaction };

/** Reconcile submitted payments after an RPC wait timeout; never release a hold without a receipt. */
export async function reconcileSubmittedPayments(limit = 50): Promise<number> {
  const rows = db.prepare("SELECT id, from_user, tx_hash FROM transactions WHERE status = 'submitted' AND tx_hash IS NOT NULL ORDER BY updated_at ASC LIMIT ?")
    .all(Math.min(100, Math.max(1, limit))) as Array<{ id: string; from_user: string; tx_hash: string }>;
  let reconciled = 0;
  for (const row of rows) {
    const status = await getReceiptStatus(row.tx_hash as `0x${string}`);
    if (!status) continue;
    const now = Date.now();
    const changes = withTransaction(() => {
      const current = db.prepare("SELECT status FROM transactions WHERE id = ?").get(row.id) as { status: string } | undefined;
      if (!current || current.status !== "submitted") return false;
      db.prepare("UPDATE transactions SET status = ?, failure_reason = ?, updated_at = ?, confirmed_at = ? WHERE id = ?")
        .run(status, status === "failed" ? "chain_reverted" : null, now, status === "confirmed" ? now : null, row.id);
      db.prepare("UPDATE fund_holds SET status = 'released', released_at = ?, release_reason = ? WHERE transaction_id = ? AND status = 'active'").run(now, status, row.id);
      db.prepare(`INSERT INTO transaction_events (id, transaction_id, status, tx_hash, failure_code, event_at) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(newId(), row.id, status, row.tx_hash, status === "failed" ? "CHAIN_REVERTED" : null, now);
      return true;
    });
    if (changes) {
      invalidateWalletView(row.from_user);
      audit(row.from_user, "payment.reconciled", { txId: row.id, status });
      audit(row.from_user, status === "confirmed" ? "payment.confirmed" : "payment.failed", { txId: row.id, status });
      audit(row.from_user, "payment.hold_released", { txId: row.id, reason: status });
      reconciled++;
    }
  }
  return reconciled;
}
