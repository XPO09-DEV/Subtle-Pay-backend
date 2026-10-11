# Subtle Pay

A UPI-style payment app on Monad testnet. The user gets a 27-character account id, a password, and a custodial wallet. They pay an alias, a saved contact, or a merchant QR in INR, USD, or any of 48 currencies. The server converts the amount and settles in MON.

Hackathon: Monad Metropolis. Backend is this repo. Frontend is separate.

## What is real

A Monad testnet payment was confirmed.

- Sender: `0xF384831F4233421660B8d35a590A20395366B3fe`
- Receiver: `0x8af044aC82Fa66C8Dbd2b02cF5C029D13C25598f`
- Transaction: [`0x2e1b73b0472134d4f573a434ba341305ae9721a72a44bba648b98971d8b91156`](https://testnet.monadvision.com/tx/0x2e1b73b0472134d4f573a434ba341305ae9721a72a44bba648b98971d8b91156)
- Chain id: `10143`

Also working: register, login, refresh, logout, home screen, alias, private contacts, 48-currency quotes, MON price in those currencies, payment history, mock withdraw, merchant bills, and capped autopay mandates.

## What is a preview

`POST /bridge/preview` shows how a Base or Arbitrum payment would reach a Monad handle. The response is `mode: "simulated"` and `settled: false`. No bridge transaction is sent. Do not treat it as a completed payment.

## How a payment works

1. Register with a password. The API returns the account id, a session, and a Monad address. The private key stays encrypted on the server.
2. Fund that address from the [Monad faucet](https://faucet.monad.xyz).
3. Pay by alias, contact name, account id, or address. The amount can be INR, EUR, USD, or another supported currency.
4. The server freezes the rate, converts to MON, signs, and broadcasts.
5. A merchant bill is the same send, opened by a QR and closed when the bill status is `paid`.

The handle is `alias@monad`, or the account id if no alias is set. It resolves to the Monad wallet. It does not yet receive funds from another chain.

## Run

```bash
cp .env.example .env
npm install
npx tsx src/server.ts
```

The API listens on `http://127.0.0.1:4000`. `GET /health` returns `{ "ok": true }`.

Node 22 is required. Do not commit `.env`, `node_modules`, or `data/`.

## Demo script

1. Register two accounts. Fund the sender.
2. Save the receiver as a contact named `ani`.
3. `GET /rates/quote?from=EUR&to=INR&amount=10`
4. `GET /rates/token?currency=INR`
5. Merchant: `POST /bills` with `{ "amount": "400", "currency": "INR" }`. Put `qr` in a QR code.
6. Customer: `GET /bills/:id`, then `POST /bills/:id/pay`.
7. Open the returned hash on MonadVision.

## Main routes

| Route | Purpose |
|---|---|
| `POST /auth/register` | Create account, wallet, and session |
| `POST /auth/login` | Session from account id and password |
| `GET /home` | Account id, alias, address, balances, rate |
| `POST /alias` | Public name |
| `POST /contacts` | Private name for someone else's account |
| `GET /rates/quote` | Any supported currency pair |
| `GET /rates/token` | MON price in that currency |
| `POST /payments/send` | Settle on Monad |
| `GET /payments` | History |
| `POST /bills` | Merchant QR bill, expires in 4 minutes |
| `POST /bills/:id/pay` | Customer pays the bill |
| `POST /mandates` | Cap for a later Monad pull |
| `POST /bridge/preview` | Labeled cross-chain preview, no settlement |

## Layout

`src/server.ts` mounts the routes. `src/lib` holds passwords, tokens, encryption, currency math, and errors. `src/chain/monad.ts` reads and sends. `src/modules` is auth, alias, contacts, rates, wallet, payments, bills, mandates, withdraw, and the bridge preview. SQLite is `data/subtle.db`.
