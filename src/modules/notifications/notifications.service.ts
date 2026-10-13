import { db } from "../../db.js";

export type PaymentNotificationType = "payment_submitted" | "payment_confirmed" | "payment_failed";

/** Notifications contain user-safe summaries only; transaction IDs/hashes are public transaction metadata. */
export function insertPaymentNotification(userId: string, transactionId: string, type: PaymentNotificationType): void {
  const copy: Record<PaymentNotificationType, { title: string; message: string }> = {
    payment_submitted: { title: "Payment submitted", message: "A payment was submitted on Monad Testnet. Confirmation may still be pending." },
    payment_confirmed: { title: "Payment confirmed", message: "A payment was confirmed on Monad Testnet." },
    payment_failed: { title: "Payment failed", message: "A payment failed on Monad Testnet. Any active fund reservation was released." },
  };
  const item = copy[type];
  db.prepare(`INSERT OR IGNORE INTO notifications (id, user_id, transaction_id, type, title, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(`${transactionId}:${userId}:${type}`, userId, transactionId, type, item.title, item.message, Date.now());
}