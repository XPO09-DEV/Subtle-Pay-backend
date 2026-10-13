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

Configure a long random `ADMIN_API_TOKEN` in the server environment. Requests require `X-Admin-Token`; comparisons are constant time and endpoints are rate-limited. Do not expose this token in the frontend or commit it to Git.

For local PowerShell development, generate a token and store it in the backend-only `.env` file:
```powershell
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$token = [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
$rng.Dispose()
(Get-Content .env) -replace '^ADMIN_API_TOKEN=.*$', ("ADMIN_API_TOKEN=" + $token) | Set-Content .env
```

- `GET /admin/overview` — account/wallet/payment counts, confirmed and unsettled payments, recent logins and opted-in regions.
- `GET /admin/users?limit=50` — account names/handles, wallet addresses, on-chain balance, active fund holds and recent transactions.
- `GET /admin/transactions?limit=50` — payment records and statuses.
- `GET /admin/login-events?limit=50&outcome=all` — login time, success/failure, reason, IP and user-agent.
- `GET /admin/merchant-applications?status=pending` — Autopay applications awaiting review.
- `POST /admin/merchant-applications/:id/review` — review an application with a JSON body such as `{"decision":"approved","note":"Reviewed"}`.
- `GET /admin/export.csv?dataset=users` — account name/handle, wallet address and creation times, last login, recent session IP/user-agent and consented region.
- `GET /admin/export.csv?dataset=payments` — in-app payments, sender/recipient addresses, amounts, statuses, timestamps, rates and transaction hashes.
- `GET /admin/export.csv?dataset=sessions` — session metadata without token secrets/hashes.
- `GET /admin/export.csv?dataset=audit` — audit actions, timestamps, details, IP and hash-chain metadata.

Account holders can review their own active sessions with `GET /me/sessions` and recent login events with `GET /me/login-events`. The account settings support a server-side hashed six-digit MPIN or the current account password for payment authorization; a one-time authorization expires after two minutes and cannot be reused. Biometric/passkey enrollment is not implemented in this prototype, so do not present it as available.

A signed receive QR is persisted per account wallet when the wallet is created. Ordinary profile edits do not regenerate it. A handle is assigned on the first profile-name save and remains fixed until the account is deleted. Deletion invalidates sessions and destroys the encrypted wallet signing-key blob while retaining transaction/audit history.

CSV is UTF-8 and opens in Excel. Exports are capped, spreadsheet formula injection is neutralized, responses are not cacheable, and sensitive key/password/token fields are excluded.

## Hackathon payment mode

The integration branch deliberately restricts `POST /payments/send` to native MON and rejects the payment flow unless `MONAD_CHAIN_ID=10143` (Monad Testnet). Other assets may be displayed by the UI for information, but they are not payable through this branch. The send form accepts a USD/INR reference value and converts it to a MON amount using the current backend rate; testnet MON is not money and market-price estimates do not give test tokens real-world value. Each newly registered custodial account wallet must be funded with testnet MON for outgoing payments and gas. No mainnet payments should be attempted from this branch.

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
| `GET /me/sessions`, `GET /me/login-events` | Active sessions and personal login history |
| `PUT /auth/mpin`, `POST /auth/payment-authorization` | MPIN setup and one-time payment approval |
| `GET /merchant/profile`, `POST /merchant/enable`, `POST /merchant/autopay-applications` | Merchant profile and Autopay application |
| `GET /admin/overview`, `GET /admin/users`, `GET /admin/transactions`, `GET /admin/login-events` | Admin monitoring of users, balances, payments and logins |
| `GET /admin/export.csv` | Admin audit/data exports |

SQLite files live under `data/`. Add new checksummed migrations; never edit applied migrations.
