# Subtle Pay Integration Reconnaissance (Step 1)

Scope inspected: `XPO09-DEV/Subtle-Pay-backend` at the integration branch base. This is a source-level reconnaissance report, not a claim of live end-to-end verification.

## Architecture map

- Runtime: Fastify 5 + TypeScript; SQLite via `better-sqlite3`; Zod validation; Node crypto.
- Startup: `src/server.ts` registers helmet, CORS, global rate limiting, request IDs, error handlers, then auth, alias, rates, wallet, payments, withdrawal, contacts, bills, mandates, bridge, asset, provider, and admin route modules.
- Configuration: `src/config.ts` validates distinct 32-byte hex JWT/password/master secrets, Monad RPC/chain ID, a relayer private key, optional contract addresses, server-only Ankr/CoinStats keys, and optional admin token.
- Database: `src/db.ts` has numbered, checksummed migrations 1–4; migration drift is refused. Tables: `users`, `wallets`, `aliases`, `refresh_tokens`, `transactions`, `withdrawals`, `idempotency_keys`, append-only `audit_log`, `contacts`, `bills`, `mandates`, and `schema_migrations`. Money uses integer micro-units; timestamps are epoch milliseconds. Several indexes exist for users/sessions/transactions/audit/contact/bill/mandate queries.
- Security primitives: Argon2id plus password pepper and lockout helpers; refresh tokens stored as SHA-256 hashes with family revocation; AES-256-GCM envelope encryption and AAD-bound encrypted wallet keys; SHA-256 hash-chained audit rows; request idempotency hashes; constant-time admin-token comparison; helmet, CORS, rate limits and generic production error responses.

## Route map

| Area | Routes |
|---|---|
| Health | `GET /health` |
| Auth/profile | `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/change-password`, `GET /me`, `GET /home`, `PUT /me/currency`, `PUT /me/profile` |
| Alias | `POST /alias`, `GET /alias/:name` |
| Wallet/assets | `GET /wallet`, `GET /assets`, `GET /api/wallet/assets` |
| Rates | `GET /rates`, `GET /rates/currencies`, `GET /rates/quote`, `GET /rates/token` |
| Market providers | `GET /market/search`, `GET /market/coins`, `GET /market/coins/:coinId`, `GET /market/coins/:coinId/charts`, `GET /market/markets`, plus CoinGecko-compatible proxy paths `/search`, `/coins/markets`, `/coins/:coinId/market_chart`, `/coins/:coinId` |
| Payments | `POST /payments/send`, `GET /payments` |
| Contacts | `GET /contacts`, `POST /contacts`, `DELETE /contacts/:name` |
| Bills/mandates | `POST /bills`, `GET /bills/:id`, `GET /bills/:id/qr`, `POST /bills/:id/pay`, `POST /mandates`, `POST /mandates/:id/run` |
| Disabled/prototype | `POST /withdraw` is disabled; `POST /bridge/preview` only previews and does not bridge |
| Admin | `GET /admin/overview`, `GET /admin/export.csv?dataset=users|payments|sessions|audit` |

## Verified gaps / risks from source inspection

1. No dedicated login-attempt/event table exists. Successful login time is derived from `audit_log`; failures are not uniformly recorded (unknown/invalid account IDs take a dummy Argon2 path and then fail).
2. No fund-hold/reservation table exists. Payments create a `pending` transaction, read on-chain balance, submit a signed transfer, and wait up to the chain helper timeout. The per-user mutex is process-local, not cross-process. A `submitted` transaction may remain unsettled until another reconciliation mechanism is added.
3. The payment API exposes only the newest 50 records; filtering/pagination are not implemented. Existing idempotency records a completed response after `run()`; a failed/uncertain submission leaves an idempotency row without a response, so the retry lifecycle needs review.
4. Admin overview is aggregate-only; user export includes addresses/profile/login/session metadata and excludes credential columns, but it does not provide current per-wallet balances or recent-transaction projections in a JSON listing.
5. Error handling sanitizes most HTTP errors, but development responses include `debug: err.message`, and the audit writer logs an error message if an append fails. These require tightening if the “never reveal logic/secrets” constraint applies in development too.
6. `GET /wallet` performs live rate and chain reads on every call. CoinStats/provider results and the Ankr wallet-assets endpoint already use TTL caches and in-flight request coalescing; native wallet-summary cache is missing.
7. Payment settlement is explicitly native MON only and checks chain ID 10143. The UI may show indexed public assets, but the payment contract rejects non-MON; this must remain explicit in the UX.
8. The code has no server endpoint for a signed/expiring payment QR; bill QR generation exists, but personal QR payload generation is client-side.
9. Production is not asserted: the README itself states this is an unaudited testnet hackathon prototype; payout and cross-chain transfer are disabled.

## Verification boundary

CI workflow currently type-checks the backend on Node 22. HTTP scripts exist for auth, payments, tokens and wallet routes. No live account-to-account testnet send was executed during source inspection. Chain/RPC timings cannot be claimed without a running, configured runtime and funded testnet wallets.
