import { formatEther } from "viem";
import { config } from "../../config.js";
import { formatMon, getNativeBalance } from "../../chain/monad.js";
import { db, type UserRow, type WalletRow } from "../../db.js";
import {
  microToDecimalString,
  minorToDecimalString,
  usdMicroToLocalMinor,
  type Currency,
} from "../../lib/currency.js";
import { notFound } from "../../lib/errors.js";
import { getRates } from "../rates/rates.service.js";
import { getActiveHoldTotalWei, reconcileActivePaymentHolds } from "../payments/holds.service.js";

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
  chainId: number;
  onChainBalanceToken: string;
  reservedToken: string;
  balanceUpdatedAt: string;
  cached?: boolean;
};

const WALLET_VIEW_CACHE_TTL_MS = 5_000;
const walletViewCache = new Map<string, { savedAt: number; value: WalletView }>();
const walletViewInFlight = new Map<string, Promise<WalletView>>();

export function invalidateWalletViewCache(userId: string): void {
  walletViewCache.delete(userId);
}

/** Cached on-chain wallet projection. Public balances reflect available funds after active reservations. */
export async function getWalletView(userId: string, force = false): Promise<WalletView> {
  const cached = walletViewCache.get(userId);
  if (!force && cached && Date.now() - cached.savedAt < WALLET_VIEW_CACHE_TTL_MS) {
    return { ...cached.value, cached: true };
  }
  if (!force) {
    const pending = walletViewInFlight.get(userId);
    if (pending) return { ...(await pending), cached: true };
  }

  const request = (async (): Promise<WalletView> => {
    await reconcileActivePaymentHolds(userId);
    const user = db.prepare("SELECT currency FROM users WHERE id = ?").get(userId) as Pick<UserRow, "currency">;
    const wallet = getWalletRow(userId);
    const currency = user.currency as Currency;
    const rates = await getRates(currency);
    const address = wallet.address as \`0x\${string}\`;

    const nativeWei = await getNativeBalance(address);
    const reservedWei = getActiveHoldTotalWei(userId);
    const availableWei = nativeWei > reservedWei ? nativeWei - reservedWei : 0n;
    const availableMon = Number(formatMon(availableWei));
    const usd = availableMon * rates.tokenUsd;
    const balanceUsdMicro = Math.max(0, Math.round(usd * 1_000_000));
    const localMinor = usdMicroToLocalMinor(balanceUsdMicro, rates.usdLocal, currency);

    const value: WalletView = {
      address: wallet.address,
      balanceToken: formatMon(availableWei),
      balanceUsd: microToDecimalString(balanceUsdMicro),
      balanceLocal: minorToDecimalString(localMinor, currency),
      currency,
      asset: "MON",
      chainId: config.MONAD_CHAIN_ID,
      onChainBalanceToken: formatMon(nativeWei),
      reservedToken: formatMon(reservedWei),
      balanceUpdatedAt: new Date().toISOString(),
    };
    walletViewCache.set(userId, { savedAt: Date.now(), value });
    if (walletViewCache.size > 1000) {
      const oldest = walletViewCache.keys().next().value;
      if (oldest) walletViewCache.delete(oldest);
    }
    return value;
  })();

  if (!force) walletViewInFlight.set(userId, request);
  try {
    return await request;
  } finally {
    if (walletViewInFlight.get(userId) === request) walletViewInFlight.delete(userId);
  }
}
