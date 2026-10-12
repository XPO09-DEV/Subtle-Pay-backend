import { serviceUnavailable } from "../../lib/errors.js";

/** No fiat payout rail is integrated; this fails closed and records no fake payout. */
export function withdrawalsUnavailable(): never {
  throw serviceUnavailable(
    "Fiat withdrawals are not enabled because no real payout provider is configured. No payout has been made.",
    "CHAIN_UNAVAILABLE"
  );
}
