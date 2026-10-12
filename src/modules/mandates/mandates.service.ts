import { db } from "../../db.js";
import { newId } from "../../lib/crypto.js";
import { badRequest, notFound } from "../../lib/errors.js";
import { audit } from "../../lib/audit.js";
import { assertCurrency, parseAmountMinor, parseUsdToMicro, localMinorToUsdMicro } from "../../lib/currency.js";
import { getRates } from "../rates/rates.service.js";
import { sendPayment } from "../payments/payments.service.js";

export async function createMandate(
  userId: string,
  merchant: string,
  cap: string,
  currencyRaw: string,
  intervalDays: number,
  ip?: string
) {
  const currency = assertCurrency(currencyRaw);
  if (intervalDays < 1 || intervalDays > 365) throw badRequest("Interval must be 1–365 days");
  const merchantRow = db.prepare("SELECT user_id FROM aliases WHERE alias = ?").get(merchant.toLowerCase()) as
    | { user_id: string }
    | undefined;
  const merchantId = merchantRow?.user_id ?? merchant;
  const exists = db.prepare("SELECT 1 FROM users WHERE id = ?").get(merchantId);
  if (!exists) throw notFound("Merchant not found");
  if (merchantId === userId) throw badRequest("You cannot mandate yourself");

  const rates = await getRates(currency);
  const entered = currency === "USD" ? parseUsdToMicro(cap) : parseAmountMinor(cap, currency);
  const capMicro = currency === "USD" ? entered : localMinorToUsdMicro(entered, rates.usdLocal, currency);
  const id = newId();
  db.prepare(
    `INSERT INTO mandates (id, user_id, merchant_id, cap_micro, currency, interval_days, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
  ).run(id, userId, merchantId, capMicro, currency, intervalDays, Date.now());
  audit(userId, "mandate.create", { id, capMicro }, ip);
  return { mandateId: id, status: "active", cap, currency, intervalDays };
}

export async function runMandate(userId: string, id: string, amount: string, ip?: string) {
  const mandate = db.prepare("SELECT * FROM mandates WHERE id = ? AND user_id = ?").get(id, userId) as
    | { id: string; merchant_id: string; cap_micro: number; currency: string; status: string }
    | undefined;
  if (!mandate) throw notFound("Mandate not found");
  if (mandate.status !== "active") throw badRequest("Mandate is not active");
  const currency = assertCurrency(mandate.currency);
  const rates = await getRates(currency);
  const entered = currency === "USD" ? parseUsdToMicro(amount) : parseAmountMinor(amount, currency);
  const micro = currency === "USD" ? entered : localMinorToUsdMicro(entered, rates.usdLocal, currency);
  if (micro > mandate.cap_micro) throw badRequest("Amount is above the mandate cap", "LIMIT_EXCEEDED");
  const paid = await sendPayment(userId, {
    to: mandate.merchant_id,
    amount,
    amountCurrency: currency,
    note: `mandate ${id}`,
  }, ip);
  audit(userId, "mandate.run", { id, txId: paid.txId }, ip);
  return { mandateId: id, payment: paid };
}
