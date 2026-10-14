import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import dotenv from "dotenv";
import Database from "better-sqlite3";
import { generatePrivateKey } from "viem/accounts";

// Local development bootstrap only. Never manufactures a new encryption key
// for a database that already contains accounts.
if (process.env.NODE_ENV === "production") process.exit(0);

const envPath = path.resolve(".env");
let source = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8").replace(/^\uFEFF/, "") : "";
const parsed = dotenv.parse(source);
const getValue = (key) => (process.env[key] ?? parsed[key] ?? "").trim();
const dbPath = path.resolve(getValue("DB_PATH") || "./data/subtle.db");

function databaseHasAccounts() {
  if (!fs.existsSync(dbPath) || fs.statSync(dbPath).size < 16) return false;
  let db;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    const hasUsers = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (!hasUsers) return false;
    return Number(db.prepare("SELECT COUNT(*) AS count FROM users").get().count) > 0;
  } catch {
    // Unknown/corrupt databases are treated as valuable: never rotate secrets
    // automatically when their relationship to encrypted keys is unknown.
    return true;
  } finally {
    try { db?.close(); } catch {}
  }
}

const critical = ["JWT_ACCESS_SECRET", "PASSWORD_PEPPER", "MASTER_KEY"];
const missingCritical = critical.filter((key) => !/^[0-9a-fA-F]{64}$/.test(getValue(key)));
if (missingCritical.length && databaseHasAccounts()) {
  console.error(
    "\nSubtle Pay startup blocked safely: an existing account database was found, but one or more required secrets are missing/invalid: " +
    missingCritical.join(", ") +
    ". Restore these exact values from your backend .env backup; do not generate replacements, because MASTER_KEY and PASSWORD_PEPPER protect existing accounts/wallets.\n"
  );
  process.exit(1);
}

const defaults = {
  NODE_ENV: "development",
  HOST: "127.0.0.1",
  PORT: "4000",
  LOG_LEVEL: "debug",
  CORS_ORIGINS: "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
  WEBAUTHN_RP_NAME: "Subtle Pay",
  WEBAUTHN_RP_ID: "localhost",
  WEBAUTHN_ORIGIN: "http://localhost:5173",
  DB_PATH: "./data/subtle.db",
  MONAD_RPC_URL: "https://testnet-rpc.monad.xyz",
  MONAD_CHAIN_ID: "10143",
  MONAD_EXPLORER_URL: "https://testnet.monadexplorer.com",
  PERPL_API_URL: "https://testnet.perpl.xyz/api",
  COINSTATS_API_BASE_URL: "https://openapiv1.coinstats.app"
};
const generated = { ...defaults };
for (const key of critical) {
  const existing = getValue(key);
  generated[key] = existing || crypto.randomBytes(32).toString("hex");
}
generated.RELAYER_PRIVATE_KEY = getValue("RELAYER_PRIVATE_KEY") || generatePrivateKey();

let changed = false;
function upsert(key, value) {
  if (getValue(key)) {
    // Align the child process environment with a valid value already present.
    process.env[key] ??= getValue(key);
    return;
  }
  const line = key + "=" + value;
  const pattern = new RegExp("^\\s*" + key + "\\s*=.*$", "m");
  if (pattern.test(source)) source = source.replace(pattern, line);
  else source += (source && !source.endsWith("\n") ? "\n" : "") + line + "\n";
  parsed[key] = value;
  process.env[key] = value;
  changed = true;
}
for (const [key, value] of Object.entries(generated)) upsert(key, value);
for (const key of critical) {
  if (!getValue(key)) upsert(key, generated[key]);
}
if (changed || !fs.existsSync(envPath)) {
  fs.mkdirSync(path.dirname(envPath), { recursive: true });
  fs.writeFileSync(envPath, source, { encoding: "utf8", mode: 0o600 });
  console.log("Subtle Pay local development configuration prepared in .env (secret values were not displayed).");
}
