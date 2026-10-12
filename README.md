# Subtle Pay Backend

Fastify + TypeScript API with SQLite persistence, Argon2id password hashing, encrypted custodial wallet keys, rotating refresh tokens, and a hash-chained audit trail.

## Run locally

Requirements: Node.js 22 or newer.

```bash
cp .env.example .env
npm ci
npm run typecheck
npm run dev
```

The API listens on `http://127.0.0.1:4000`; `GET /health` reports health. Generate distinct values for `JWT_ACCESS_SECRET`, `PASSWORD_PEPPER`, and `MASTER_KEY`, then configure a separate long random `ADMIN_API_TOKEN`. Keep `.env`, `data/`, wallet keys and provider credentials out of Git.

## Provider integrations

### Ankr

`GET /api/wallet/assets?address=0x...` proxies account-balance discovery on the server. It validates EVM addresses, paginates indexed balances, reads native MON via the configured Monad RPC where available, coalesces concurrent requests, caches for 60 seconds, and applies a route-specific rate limit. Results are public-chain data and do not prove the caller owns a wallet. Network coverage depends on provider plan/support and indexer availability.

Set `ANKR_API_KEY` only in the backend environment. It is never returned to clients.

### CoinStats

`GET /market/search?q=bitcoin`, `GET /market/coins`, `GET /market/coins/:coinId`, `GET /market/coins/:coinId/charts?period=3m`, and `GET /market/markets` proxy CoinStats using server-only `X-API-KEY` authentication, request coalescing, short-lived caches and route-level rate limits.

Set `COINSTATS_API_KEY` only on the server. The default API origin is `https://openapiv1.coinstats.app`.

## Account, privacy and exports

The database records account/wallet creation times, authentication events, refresh-session IP/user-agent/time metadata and payments created through this backend. A new versioned migration adds display name plus an optional user-supplied region and consent timestamp. Region is never inferred from IP and is only returned/exported after the user opts in. Publish a privacy notice and define retention before production.

Configure a long random `ADMIN_API_TOKEN` in the server environment. Requests require `X-Admin-Token`; comparisons are constant time and endpoints are rate-limited.

- `GET /admin/overview` — account/wallet/payment counts, confirmed and unsettled payments, recent logins and opted-in regions.
- `GET /admin/export.csv?dataset=users` — account name/handle, wallet address and creation times, last login, recent session IP/user-agent and consented region.
- `GET /admin/export.csv?dataset=payments` — in-app payments, sender/recipient addresses, amounts, statuses, timestamps, rates and transaction hashes.
- `GET /admin/export.csv?dataset=sessions` — session metadata without token secrets/hashes.
- `GET /admin/export.csv?dataset=audit` — audit actions, timestamps, details, IP and hash-chain metadata.

CSV is UTF-8 and opens in Excel. Exports are capped, spreadsheet formula injection is neutralized, responses are not cacheable, and sensitive key/password/token fields are excluded.

## Commercial launch status — important

This backend is **not yet certified production-ready**. The configured chain may still be Monad testnet (chain ID 10143). A production rollout needs a verified mainnet RPC/chain ID, deployed and audited contracts, funded production relayer, key rotation/recovery, monitoring, backups/restore tests, abuse controls and an independent security review.

The fiat-withdrawal route is disabled until a real payout provider is integrated. Cross-chain bridging is disabled and no bridge transaction is implemented. The payment service supports only its configured Monad settlement path. Review applicable KYC/AML/sanctions, consumer protection, custody, privacy, retention, accounting and tax requirements with qualified professionals before accepting commercial users.

## Main routes

| Route | Purpose |
|---|---|
| `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout` | Accounts and sessions |
| `GET /me`, `GET /home`, `PUT /me/profile` | Authenticated identity/profile |
| `GET /wallet` | Custodial Monad wallet summary |
| `POST /payments/send`, `GET /payments` | Payments and history |
| `GET /api/wallet/assets` | Rate-limited Ankr balance proxy |
| `PUT /me/profile` | Profile name and explicit region-sharing consent |
| `GET /market/*` | Cached CoinStats market proxy |
| `GET /admin/overview`, `GET /admin/export.csv` | Admin view and exports |

SQLite files live under `data/`. Add new checksummed migrations; never edit applied migrations.
