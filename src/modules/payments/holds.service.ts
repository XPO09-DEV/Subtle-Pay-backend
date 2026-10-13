import type { Hash } from "viem";
import { publicClient } from "../../chain/monad.js";
import { db, withTransaction } from "../../db.js";
import { audit } from "../../lib/audit.js";

type ActiveHoldRow = { amount_wei: string };
type PendingReceiptRow = { id: string; tx_hash: string };

/** Active reservation totals are stored as decimal strings to avoid SQLite/JS integer overflow. */
export function getActiveHoldTotalWei(userId: string): bigint {
  const rows = db.prepare(
    "SELECT amount_wei FROM fund_holds WHERE user_id = ? AND status = 'active'"
  ).all(userId) as ActiveHoldRow[];
  return rows.reduce((total, row) => total + BigInt(row.amount_wei), 0n);
}

/** Reconcile submitted payments without exposing any key material to the caller. */
export async function reconcileActivePaymentHolds(userId: string): Promise<void> {
  const rows = db.prepare(`
    SELECT t.id, t.tx_hash
      FROM transactions t
      JOIN fund_holds h ON h.transaction_id = t.id
     WHERE h.user_id = ? AND h.status = 'active'
       AND t.status = 'submitted' AND t.tx_hash IS NOT NULL
     ORDER BY t.created_at ASC
     LIMIT 20
  `).all(userId) as PendingReceiptRow[];

  for (const row of rows) {
    let outcome: "confirmed" | "failed";
    try {
      const receipt = await publicClient.getTransactionReceipt({ hash: row.tx_hash as Hash });
      outcome = receipt.status === "success" ? "confirmed" : "failed";
    } catch {
      // No receipt yet (or RPC failure): leave the hold active; do not guess that funds are free.
      continue;
    }

    const now = Date.now();
    let changed = false;
    withTransaction(() => {
      const update = db.prepare(
        "UPDATE transactions SET status = ?, confirmed_at = ?, updated_at = ? WHERE id = ? AND status = 'submitted'"
      ).run(outcome, outcome === "confirmed" ? now : null, now, row.id);
      if (update.changes !== 1) return;
      db.prepare(
        "UPDATE fund_holds SET status = ?, updated_at = ?, resolved_at = ? WHERE transaction_id = ? AND status = 'active'"
      ).run(outcome === "confirmed" ? "settled" : "released", now, now, row.id);
      changed = true;
    });
    if (changed) audit(userId, `payment.${outcome}`, { transactionId: row.id, txHash: row.tx_hash });
  }
}
