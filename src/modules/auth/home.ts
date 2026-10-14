import { getMe } from "./auth.service.js";
import { getWalletView } from "../wallet/wallet.service.js";

/** One call for the app home screen: identity, wallet, and the live rate. */
export async function getHome(userId: string, forceRefresh = false) {
  const me = getMe(userId);
  const wallet = await getWalletView(userId, forceRefresh);
  return {
    accountId: me.accountId, alias: me.alias, displayName: me.displayName,
    region: me.region, regionConsentAt: me.regionConsentAt, currency: me.currency,
    address: wallet.address, balanceToken: wallet.balanceToken, balanceUsd: wallet.balanceUsd,
    stableBalanceToken: wallet.stableBalanceToken,
    balanceLocal: wallet.balanceLocal, asset: wallet.asset, chainId: wallet.chainId, rates: wallet.rates,
  };
}
