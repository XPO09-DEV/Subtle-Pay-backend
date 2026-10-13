# Subtle Pay integration report

## Step 1 — Reconnaissance and gap analysis

Repositories: React 19 + TypeScript + Vite frontend (subtle-pay-frontend) and Fastify 5 + TypeScript + better-sqlite3 backend (Subtle-Pay-backend).

Frontend map: active screens are Dashboard/Wallet, Send, Receive, Activity, Notifications, Merchant and More/Settings, with AccountGate handling login/register. Components include WalletCard, QRScanner, QRCodeCard, QRCodeModal, CurrencyPreference and transaction/activity rows. The account service is src/services/accountService.ts; legacy screens use src/api/client.ts. Browser state previously persisted auth material and contact/currency/asset data locally; integration removes credential persistence, moves contacts/currency preferences to API calls, and displays only backend-returned Monad Testnet MON for spendable balance. Local storage remains only for opt-in navigation/asset display preferences, never balances or credentials.

Backend map: server registers health, auth/profile/home, alias, rates, wallet, payments, QR, withdrawals, contacts, bills, mandates, bridge, assets, providers and admin routes. Security boundaries are middleware/auth.ts, middleware/idempotency.ts, lib/password.ts, lib/kms.ts, lib/tokens.ts, lib/audit.ts, lib/errors.ts, and chain/monad.ts. Existing tables include users, wallets, aliases, refresh_tokens, transactions, audit_log, idempotency_keys, contacts, withdrawals, bills and mandates.

Initial gaps: alternate frontend session/API clients, local contacts/currency preferences, broad multichain asset selection, incomplete login-event rows, no dedicated reservation ledger, insufficiently explicit transaction status history, unsigned/client-built QR path, admin exports containing unnecessary raw operational fields, and incomplete cache-bypass APIs.

## Step 2 — Database and transaction tracking

A new numbered, SHA-256-checksummed tracking migration at src/migrations/005-login-fund-holds-transaction-events.ts creates a dedicated integration_migrations ledger. This intentionally leaves existing schema migrations 1–4 and their checksums untouched.

- login_events: successful/failed login and registration timestamps, account ID where known, IP, bounded user-agent, request ID, reason, and a SHA-256 hash of the normalized attempted account identifier.
- fund_holds: active/released native MON reservations associated with a transaction. On-chain atomic amount is stored as decimal integer text to preserve bigint precision; USD values are integer micro-units.
- transaction_events: append-only status transitions, chain hash, bounded failure code, metadata and epoch-ms timestamp. SQLite triggers reject updates/deletes.
- New query indexes cover login/account history, active holds, transaction event history, recent transactions, user creation and alias lookup.

## Step 3 — Security hardening

- Existing Argon2id, password pepper, envelope encryption, short-lived signing scope, secret zeroization and hashed rotating refresh tokens/family revocation are preserved.
- Backend config rejects any chain ID except 10143, and the chain adapter checks the RPC's actual remote chain ID before reading or submitting transactions.
- QR payloads are server-generated and HMAC-SHA-256 signed using a domain-separated key derived with HKDF from MASTER_KEY; verification uses timing-safe comparison and checks testnet chain.
- Error handling/logging no longer serializes raw exception objects or arbitrary exception message strings. Authentication lock state is reported as generic invalid credentials. Admin viewers never select password_hash, enc_priv_key or refresh token values.
- Register, login, payment send and QR endpoints have specific rate limits in addition to the global limit. Payment sends require a valid idempotency key; unresolved keys are rejected rather than rebroadcast blindly.

## Step 4 — API and optimization

- GET /home?refresh=true and GET /wallet?refresh=true allow explicit cache bypass. Wallet reads use a 10-second per-account cache and coalesce concurrent requests; ordinary cached reads avoid repeated RPC calls.
- The payable asset list and send service are native MON-only. Testnet chain ID checks fail closed. Bridge and fiat payout functionality remain gated; this patch does not create real-value transfer pathways.
- Payment sends atomically write transaction + active hold + initial lifecycle event before signing/submission. Submitted hash and status transitions are recorded, then reservations are released only after a confirmed or failed receipt. A background reconciler retries receipt checks every 15 seconds and keeps reservations active when the outcome is unknown.
- Transaction history supports bounded page size and a timestamp/ID cursor.

## Step 5 — Frontend wiring

- Both API clients use in-memory access tokens plus backend HttpOnly refresh cookies, with credentialed no-store requests; no access or refresh token is saved into localStorage.
- Wallet balances no longer come from browser RPC or demo/mock assets; only backend MON data is rendered.
- Contacts and currency preferences load/save through the backend.
- Receive uses GET /qr/pay. The scanner parses supported shapes; signed Subtle Pay QRs must pass POST /qr/verify before embedded amount/currency prefills Send. Address-only QR fills a recipient without asserting a trusted amount/network.
- Activity and Notifications use backend payment records with loading/empty/error/refresh handling and bounded pagination.

## Step 6 — Platform tracking and admin

- Admin-token-protected GET /admin/users returns an allowlisted projection: account ID, display name, alias, address, currency, last login, transaction counts, native MON balances/reservations and recent transaction summaries.
- GET /admin/transactions returns safe transaction lifecycle metadata. Exported user/payment datasets omit credential columns; session export derives from login events, and audit export omits IP and arbitrary free-form detail payloads.
- Platform sends get transaction and audit records; login success/failure and hold/submission/confirmation/release are tracked.

## Step 7 — Verification status

Passed: source syntax parse checks for 40 backend and 40 frontend TypeScript/TSX files; migration SQL applied in SQLite during inspection with tracking tables STRICT; preservation check showed existing migration SQL versions 1–4 unchanged; chain ID and response allowlists reviewed statically.

Not completed: npm dependency installation/build and live end-to-end chain flow. npm ci --offline could not install pinned zod@4.6.5 because the package is not cached, and the attempted normal install did not produce usable node_modules. No testnet RPC endpoint, faucet-funded test account or admin token was supplied. Consequently there is no live register→send→receipt→admin test and no measured <50 ms cached / <200 ms live latency claim.

Remaining manual verification: run npm ci, backend typecheck and frontend build; test cookies/CORS over selected origins; verify camera permissions in a real browser (HTTPS/localhost needed); run payment lifecycle with faucet MON; exercise receipt-timeout reconciliation and failed/reverted transactions; measure warm/cold latency and inspect query plans against representative data. Only native faucet MON on Monad Testnet is in scope. This is a hackathon/testnet integration and not a production financial-service certification.

## Run together

1. Use Node.js 22+ and run npm ci in each repo.
2. Backend: copy .env.example to an untracked .env; generate different random 32-byte hex values for JWT_ACCESS_SECRET, PASSWORD_PEPPER and MASTER_KEY; configure Monad Testnet RPC and a faucet-funded test-only relayer key; keep MONAD_CHAIN_ID=10143. Never set server secrets as Vite variables or commit .env.
3. Start API with npm run dev (default port 4000) and set exact frontend origin in CORS_ORIGINS.
4. Frontend: set VITE_SUBTLEPAY_API_BASE_URL=http://localhost:4000 in an untracked local .env and run npm run dev. Credentialed cookie requests require matching CORS origin and suitable HTTPS/same-site setup.
5. Check /health, then test register/login, home/refresh, QR generation and verification, send, history, reconciliation and admin routes using only faucet test tokens.
