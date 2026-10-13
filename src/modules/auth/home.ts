import { getMe } from "./auth.service.js";
import { getRates } from "../rates/rates.service.js";
import { getWalletView } from "../wallet/wallet.service.js";

/** One call for the app home screen: identity, wallet, and the live rate. */
export async function getHome(userId: string, force = false) {
  const me = getMe(userId);
  const [wallet, rates] = await Promise.all([getWalletView(userId, force), getRates(me.currency)]);
  return {
    accountId: me.accountId,
    alias: me.alias,
    displayName: me.displayName,
    region: me.region,
    regionConsentAt: me.regionConsentAt,
    currency: me.currency,
    address: wallet.address,
    balanceToken: wallet.balanceToken,
    balanceUsd: wallet.balanceUsd,
    balanceLocal: wallet.balanceLocal,
    asset: wallet.asset,
    chainId: wallet.chainId,
    onChainBalanceToken: wallet.onChainBalanceToken,
    reservedToken: wallet.reservedToken,
    balanceUpdatedAt: wallet.balanceUpdatedAt,
    rates,
  };
}
