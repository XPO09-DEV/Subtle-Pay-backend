import { isAddress, type Hash } from "viem";
import { config } from "../../config.js";
import {
  formatMon,
  formatToken,
  estimateNativeTransferFee,
  getNativeBalance,
  getTokenBalance,
  sendNative,
  sendToken,
  waitConfirmed,
} from "../../chain/monad.js";
import { db, withTransaction, type TransactionRow } from "../../db.js";
import { newId } from "../../lib/crypto.js";
import {
  assertPaymentWithinLimits,
  localMinorToUsdMicro,
  microToDecimalString,
  minorToDecimalString,
  parseAmountMinor,
  parseUsdToMicro,
  usdMicroToLocalMinor,
  type Currency,
} from "../../lib/currency.js";
import { badRequest, insufficientFunds, notFound, unprocessable } from "../../lib/errors.js";
import { withDecryptedSecret } from "../../lib/kms.js";
import { audit } from "../../lib/audit.js";
import { normalizeAlias } from "../alias/alias.service.js";
import { getRates } from "../rates/rates.service.js";
import { getWalletRow, invalidateWalletViewCache } from "../wallet/wallet.service.js";
import { getActiveHoldTotalWei } from "./holds.service.js";
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

export async function sendPayment(
  userId: string,
  input: { to: string; amount: string | number; amountCurrency: string; note?: string; asset?: string },
  ip?: string
) {
  return exclusive(userId, async () => {
    const requestedAsset = (input.asset ?? "MON").trim().toUpperCase();
    if (requestedAsset !== "MON") {
      throw unprocessable("Hackathon payments are restricted to native MON on Monad Testnet. Other displayed assets are not transferable in this build.", "CHAIN_UNAVAILABLE");
    }
    if (config.MONAD_CHAIN_ID !== 10143) {
      throw unprocessable("Native MON payments are locked to Monad Testnet (chain ID 10143) for this hackathon build.", "CHAIN_UNAVAILABLE");
    }
    const currency = input.amountCurrency.trim().toUpperCase() as Currency;
    const displayMinorOrMicro = parseAmount(input.amount, currency);
    const rates = await getRates(currency);
    const usdMicro = currency === "USD" ? displayMinorOrMicro : localMinorToUsdMicro(displayMinorOrMicro, rates.usdLocal, currency);
    assertPaymentWithinLimits(usdMicro);
    if (input.note && input.note.length > 140) throw badRequest("Note is too long");

    const from = getWalletRow(userId);
    const dest = await resolveDestination(input.to, userId);
    if (dest.address.toLowerCase() === from.address.toLowerCase()) {
      throw unprocessable("You cannot pay yourself", "SELF_PAYMENT");
    }

    // Keep hackathon settlement native-only even if a token address exists in local configuration.
    const stable = false;
    const tokenBase = stable ? BigInt(usdMicro) : monWei(usdMicro, rates.tokenUsd);
    if (tokenBase <= 0n) throw badRequest("Amount is too small", "INVALID_AMOUNT");

    const balance = stable ? await getTokenBalance(from.address as `0x${string}`) : await getNativeBalance(from.address as `0x${string}`);
    if (balance === null || balance < tokenBase) throw insufficientFunds();

    const txId = newId();
    const now = Date.now();
    const estimatedFeeWei = stable
      ? 0n
      : await estimateNativeTransferFee(
          from.address as `0x${string}`,
          dest.address as `0x${string}`,
          tokenBase
        );
    const reservedWei = tokenBase + estimatedFeeWei;

    // Recheck all active holds while holding SQLite's IMMEDIATE write lock, then
    // reserve this amount atomically with the transaction record.
    withTransaction(() => {
      const activeHolds = getActiveHoldTotalWei(userId);
      if (!stable && balance < activeHolds + reservedWei) throw insufficientFunds();
      db.prepare(
        `INSERT INTO transactions
           (id, from_user, to_user, from_address, to_address, amount_micro, display_currency, fx_rate, status, note, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`
      ).run(txId, userId, dest.userId, from.address, dest.address, usdMicro, currency, rates.usdLocal, input.note ?? null, now, now);
      db.prepare(
        `INSERT INTO fund_holds (id, transaction_id, user_id, amount_wei, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'active', ?, ?)`
      ).run(txId, txId, userId, reservedWei.toString(), now, now);
    });
    invalidateWalletViewCache(userId);

    let submittedHash: Hash | null = null;
    try {
      const hash = await withDecryptedSecret(from.enc_priv_key, { userId, address: from.address }, async (secret) => {
        const key = `0x${secret.toString("hex")}` as `0x${string}`;
        return stable
          ? sendToken(key, dest.address as `0x${string}`, tokenBase)
          : sendNative(key, dest.address as `0x${string}`, tokenBase);
      });

      submittedHash = hash;

      // Persist the hash immediately after submission. A timeout waiting for a
      // receipt must not erase a potentially live transaction or its reservation.
      withTransaction(() => {
        db.prepare(
          `UPDATE transactions SET status = 'submitted', tx_hash = ?, updated_at = ? WHERE id = ?`
        ).run(hash, Date.now(), txId);
      });
      invalidateWalletViewCache(userId);

      const status = await waitConfirmed(hash);
      const finishedAt = Date.now();
      withTransaction(() => {
        db.prepare(
          `UPDATE transactions SET status = ?, tx_hash = ?, updated_at = ?, confirmed_at = ? WHERE id = ?`
        ).run(status, hash, finishedAt, status === "confirmed" ? finishedAt : null, txId);
        db.prepare(
          `UPDATE fund_holds SET status = ?, updated_at = ?, resolved_at = ? WHERE transaction_id = ? AND status = 'active'`
        ).run(status === "confirmed" ? "settled" : status === "failed" ? "released" : "active", finishedAt, status === "submitted" ? null : finishedAt, txId);
      });
      invalidateWalletViewCache(userId);
      audit(userId, "payment.send", { txId, status, usdMicro }, ip);
      return {
        txId,
        status,
        tokenAmount: stable ? formatToken(tokenBase, 6) : formatMon(tokenBase),
        usdValue: microToDecimalString(usdMicro),
        txHash: hash,
      };
    } catch (err) {
      const failedAt = Date.now();
      withTransaction(() => {
        if (submittedHash) {
          // The RPC accepted a transaction. If persisting the receipt/status failed,
          // keep it submitted and retain the hold until a later receipt reconciliation.
          db.prepare(
            `UPDATE transactions SET status = 'submitted', tx_hash = COALESCE(tx_hash, ?), failure_reason = NULL, updated_at = ? WHERE id = ? AND status IN ('pending','submitted')`
          ).run(submittedHash, failedAt, txId);
        } else {
          db.prepare(
            `UPDATE transactions SET status = 'failed', failure_reason = ?, updated_at = ? WHERE id = ? AND status = 'pending'`
          ).run("chain", failedAt, txId);
          db.prepare(
            `UPDATE fund_holds SET status = 'released', updated_at = ?, resolved_at = ? WHERE transaction_id = ? AND status = 'active'`
          ).run(failedAt, failedAt, txId);
        }
      });
      invalidateWalletViewCache(userId);
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
    const row = db.prepare("SELECT user_id, address FROM wallets WHERE lower(address) = lower(?)").get(raw) as
      | { user_id: string; address: string }
      | undefined;
    return { address: row?.address ?? raw, userId: row?.user_id ?? null };
  }
  const alias = normalizeAlias(raw);
  const row = db
    .prepare(
      `SELECT a.user_id, w.address
         FROM aliases a JOIN wallets w ON w.user_id = a.user_id
        WHERE a.alias = ?`
    )
    .get(alias) as { user_id: string; address: string } | undefined;
  if (!row) throw notFound("No account uses that name", "ALIAS_NOT_FOUND");
  return { address: row.address, userId: row.user_id };
}

export function listPayments(userId: string) {
  const user = db.prepare("SELECT currency FROM users WHERE id = ?").get(userId) as { currency: Currency };
  const rows = db
    .prepare(
      `SELECT t.*,
              fa.alias AS from_alias,
              ta.alias AS to_alias
         FROM transactions t
         LEFT JOIN aliases fa ON fa.user_id = t.from_user
         LEFT JOIN aliases ta ON ta.user_id = t.to_user
        WHERE t.from_user = ? OR t.to_user = ?
        ORDER BY t.created_at DESC
        LIMIT 50`
    )
    .all(userId, userId) as Array<TransactionRow & { from_alias: string | null; to_alias: string | null }>;

  return rows.map((row) => {
    const outgoing = row.from_user === userId;
    const localMinor = usdMicroToLocalMinor(row.amount_micro, row.fx_rate, row.display_currency as Currency);
    return {
      id: row.id,
      direction: outgoing ? "out" : "in",
      counterparty: outgoing ? row.to_alias ?? row.to_address : row.from_alias ?? row.from_address,
      usdValue: microToDecimalString(row.amount_micro),
      localValue: minorToDecimalString(localMinor, row.display_currency as Currency),
      displayCurrency: row.display_currency,
      status: row.status,
      txHash: row.tx_hash,
      createdAt: new Date(row.created_at).toISOString(),
    };
  });
}

export { withTransaction };
