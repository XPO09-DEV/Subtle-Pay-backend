import { formatEther, type Address } from "viem";
import { config } from "../../config.js";
import { formatMon, formatToken, getNativeBalance, getTokenBalance } from "../../chain/monad.js";
import { db, type UserRow, type WalletRow } from "../../db.js";
import { microToDecimalString, minorToDecimalString, usdMicroToLocalMinor, type Currency } from "../../lib/currency.js";
import { notFound } from "../../lib/errors.js";
import { getRates } from "../rates/rates.service.js";

export function getWalletRow(userId: string): WalletRow {
  const row = db.prepare("SELECT * FROM wallets WHERE user_id = ?").get(userId) as WalletRow | undefined;
  if (!row) throw notFound("Wallet not found");
  return row;
}

type WalletView = {
  address: string;
  balanceToken: string;
  balanceUsd: string;
  balanceLocal: string;
  currency: Currency;
  asset: "MON";
  chainId: typeof config.MONAD_CHAIN_ID;
  reservedToken: string;
  stableBalanceToken: string | null;
  rates: Awaited<ReturnType<typeof getRates>>;
  updatedAt: string;
  cached: boolean;
};

const WALLET_VIEW_TTL_MS = 10_000;
const walletViewCache = new Map<string, { savedAt: number; value: WalletView }>();
const walletViewInflight = new Map<string, Promise<WalletView>>();

export async function getWalletView(userId: string, force = false) {
  const cached = walletViewCache.get(userId);
  if (!force && cached && Date.now() - cached.savedAt < WALLET_VIEW_TTL_MS) return { ...cached.value, cached: true };
  const pending = !force ? walletViewInflight.get(userId) : undefined;
  if (pending) return { ...(await pending), cached: true };
  const request: Promise<WalletView> = (async () => {
    const user = db.prepare("SELECT currency FROM users WHERE id = ?").get(userId) as Pick<UserRow, "currency">;
    const wallet = getWalletRow(userId);
    const currency = user.currency as Currency;
    const address = wallet.address as Address;
    const [rates, nativeWei, stableRaw, holds] = await Promise.all([
      getRates(currency), getNativeBalance(address), getTokenBalance(address).catch(() => null),
      Promise.resolve(db.prepare("SELECT asset, amount_atomic FROM fund_holds WHERE user_id = ? AND status = 'active'").all(userId) as Array<{ asset: string; amount_atomic: string }>),
    ]);
    const reservedWei = holds.filter((row) => row.asset === "MON").reduce((total, row) => total + BigInt(row.amount_atomic), 0n);
    const reservedStable = holds.filter((row) => row.asset === "USDC").reduce((total, row) => total + BigInt(row.amount_atomic), 0n);
    const availableWei = nativeWei > reservedWei ? nativeWei - reservedWei : 0n;
    const stableBalanceToken = stableRaw === null ? null : formatToken(stableRaw > reservedStable ? stableRaw - reservedStable : 0n, 6);
    const usd = Number(formatEther(availableWei)) * rates.tokenUsd;
    const balanceUsdMicro = Math.max(0, Math.round(usd * 1_000_000));
    const localMinor = usdMicroToLocalMinor(balanceUsdMicro, rates.usdLocal, currency);
    return {
      address: wallet.address, balanceToken: formatMon(availableWei),
      balanceUsd: microToDecimalString(balanceUsdMicro), balanceLocal: minorToDecimalString(localMinor, currency),
      currency, asset: "MON", chainId: config.MONAD_CHAIN_ID, reservedToken: formatMon(reservedWei), stableBalanceToken,
      rates, updatedAt: new Date().toISOString(), cached: false,
    };
  })();
  walletViewInflight.set(userId, request);
  try {
    const value = await request;
    walletViewCache.set(userId, { savedAt: Date.now(), value });
    if (walletViewCache.size > 500) {
      const oldestKey = walletViewCache.keys().next().value;
      if (oldestKey) walletViewCache.delete(oldestKey);
    }
    return value;
  } finally {
    if (walletViewInflight.get(userId) === request) walletViewInflight.delete(userId);
  }
}
export function invalidateWalletView(userId: string): void { walletViewCache.delete(userId); }
