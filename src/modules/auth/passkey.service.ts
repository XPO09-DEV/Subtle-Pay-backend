import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from "@simplewebauthn/server";
import { db, withTransaction } from "../../db.js";
import { audit } from "../../lib/audit.js";
import { newId, normalizeAccountId, isValidAccountId } from "../../lib/crypto.js";
import { badRequest, conflict, notFound, unauthorized } from "../../lib/errors.js";
import { verifyPassword } from "../../lib/password.js";
import { config } from "../../config.js";
import {
  getPaymentIntentHash,
  issuePasskeyPaymentAuthorizationForIntent,
  type PaymentIntent,
} from "./paymentAuth.service.js";

type ChallengePurpose = "registration" | "login" | "payment";
type ChallengeRow = {
  id: string;
  user_id: string;
  purpose: ChallengePurpose;
  challenge: string;
  intent_hash: string | null;
  expires_at: number;
  used_at: number | null;
  created_at: number;
};
type CredentialRow = {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  transports: string;
  device_name: string;
  device_type: "singleDevice" | "multiDevice";
  backed_up: number;
  created_at: number;
  last_used_at: number | null;
};
type StoredTransports = NonNullable<WebAuthnCredential["transports"]>;

const CHALLENGE_TTL_MS = 120_000;

function parseTransports(value: string): StoredTransports {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [] as unknown as StoredTransports;
    const allowed = new Set(["ble", "hybrid", "internal", "nfc", "usb", "smart-card"]);
    return parsed.filter((item): item is string => typeof item === "string" && allowed.has(item)) as StoredTransports;
  } catch {
    return [] as unknown as StoredTransports;
  }
}

function saveChallenge(userId: string, purpose: ChallengePurpose, challenge: string, intentHash: string | null = null): string {
  const id = newId();
  const now = Date.now();
  withTransaction(() => {
    db.prepare("DELETE FROM webauthn_challenges WHERE expires_at <= ? OR (used_at IS NOT NULL AND used_at < ?)")
      .run(now, now - 86_400_000);
    db.prepare("INSERT INTO webauthn_challenges (id, user_id, purpose, challenge, intent_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)")
      .run(id, userId, purpose, challenge, intentHash, now + CHALLENGE_TTL_MS, now);
  });
  return id;
}

/** Atomically marks a short-lived challenge used before doing any cryptographic verification. */
function consumeChallenge(id: string, purpose: ChallengePurpose, userId?: string): ChallengeRow {
  const now = Date.now();
  const row = withTransaction(() => {
    const query = userId
      ? db.prepare("SELECT * FROM webauthn_challenges WHERE id = ? AND purpose = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?")
      : db.prepare("SELECT * FROM webauthn_challenges WHERE id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?");
    const found = (userId ? query.get(id, purpose, userId, now) : query.get(id, purpose, now)) as ChallengeRow | undefined;
    if (!found) return null;
    const updated = db.prepare("UPDATE webauthn_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?")
      .run(now, id, now).changes;
    return updated === 1 ? found : null;
  });
  if (!row) throw unauthorized("The passkey challenge is expired, already used, or does not match this request.", "INVALID_CREDENTIALS");
  return row;
}

function credentialDescriptors(userId: string) {
  return (db.prepare("SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC")
    .all(userId) as Array<{ credential_id: string; transports: string }>).map((row) => ({
      id: row.credential_id,
      transports: parseTransports(row.transports),
    }));
}

function loadCredential(credentialId: string): CredentialRow | undefined {
  return db.prepare("SELECT * FROM webauthn_credentials WHERE credential_id = ?")
    .get(credentialId) as CredentialRow | undefined;
}

function toWebAuthnCredential(row: CredentialRow): WebAuthnCredential {
  return {
    id: row.credential_id,
    publicKey: new Uint8Array(Buffer.from(row.public_key, "base64url")),
    counter: row.counter,
    transports: parseTransports(row.transports),
  };
}

async function verifyAssertionForChallenge(
  challenge: ChallengeRow,
  response: AuthenticationResponseJSON,
  expectedUserId?: string,
  ip?: string,
): Promise<CredentialRow> {
  if (!response || typeof response.id !== "string" || response.id.length < 16 || response.id.length > 2048) {
    throw unauthorized("Passkey verification failed.", "INVALID_CREDENTIALS");
  }
  const row = loadCredential(response.id);
  if (!row || row.user_id !== challenge.user_id || (expectedUserId && row.user_id !== expectedUserId)) {
    audit(challenge.user_id, "security.passkey_assertion_failed", { reason: "credential_mismatch", purpose: challenge.purpose }, ip);
    throw unauthorized("Passkey verification failed.", "INVALID_CREDENTIALS");
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.WEBAUTHN_ORIGIN,
      expectedRPID: config.WEBAUTHN_RP_ID,
      credential: toWebAuthnCredential(row),
      requireUserVerification: true,
    });
  } catch {
    audit(row.user_id, "security.passkey_assertion_failed", { reason: "verification_rejected", purpose: challenge.purpose }, ip);
    throw unauthorized("Passkey verification failed. Try again or use your account password.", "INVALID_CREDENTIALS");
  }

  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    audit(row.user_id, "security.passkey_assertion_failed", { reason: "user_verification_required", purpose: challenge.purpose }, ip);
    throw unauthorized("Your device did not verify you. Try again using device verification.", "INVALID_CREDENTIALS");
  }

  const nextCounter = verification.authenticationInfo.newCounter;
  if (row.counter > 0 && nextCounter <= row.counter) {
    audit(row.user_id, "security.passkey_counter_rejected", { purpose: challenge.purpose }, ip);
    throw unauthorized("This passkey returned a stale signature counter. Use another registered passkey or your password.", "INVALID_CREDENTIALS");
  }

  const now = Date.now();
  const updated = withTransaction(() => db.prepare(
    "UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE credential_id = ? AND user_id = ? AND counter = ?"
  ).run(Math.max(row.counter, nextCounter), now, row.credential_id, row.user_id, row.counter).changes);
  if (updated !== 1) {
    audit(row.user_id, "security.passkey_counter_rejected", { purpose: challenge.purpose, reason: "concurrent_counter_change" }, ip);
    throw unauthorized("This passkey was used concurrently. Please retry the authentication.", "INVALID_CREDENTIALS");
  }
  audit(row.user_id, "security.passkey_assertion_verified", { purpose: challenge.purpose, deviceType: row.device_type }, ip);
  return { ...row, counter: Math.max(row.counter, nextCounter), last_used_at: now };
}

export async function createPasskeyRegistrationOptions(
  userId: string,
  currentPassword: string,
): Promise<{ challengeId: string; options: Awaited<ReturnType<typeof generateRegistrationOptions>> }> {
  const user = db.prepare("SELECT id, password_hash, display_name FROM users WHERE id = ? AND deleted_at IS NULL")
    .get(userId) as { id: string; password_hash: string; display_name: string | null } | undefined;
  if (!user || !(await verifyPassword(user.password_hash, currentPassword))) {
    audit(userId, "security.passkey_registration_failed", { reason: "reauthentication_failed" });
    throw unauthorized("Confirm your current account password before enabling a passkey.", "INVALID_CREDENTIALS");
  }

  const existing = credentialDescriptors(userId);
  const options = await generateRegistrationOptions({
    rpName: config.WEBAUTHN_RP_NAME,
    rpID: config.WEBAUTHN_RP_ID,
    userID: Buffer.from(user.id, "utf8"),
    userName: user.id,
    userDisplayName: user.display_name?.trim() || user.id,
    attestationType: "none",
    timeout: CHALLENGE_TTL_MS,
    excludeCredentials: existing,
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
    },
    supportedAlgorithmIDs: [-7, -257],
  });
  const challengeId = saveChallenge(userId, "registration", options.challenge);
  return { challengeId, options };
}

export async function verifyPasskeyRegistration(
  userId: string,
  challengeId: string,
  response: RegistrationResponseJSON,
  requestedName: string | undefined,
  ip?: string,
): Promise<{ credentialId: string; deviceName: string; createdAt: number }> {
  const challenge = consumeChallenge(challengeId, "registration", userId);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.WEBAUTHN_ORIGIN,
      expectedRPID: config.WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });
  } catch {
    audit(userId, "security.passkey_registration_failed", { reason: "verification_rejected" }, ip);
    throw unauthorized("Passkey registration could not be verified. Retry from the configured Subtle Pay domain.", "INVALID_CREDENTIALS");
  }
  if (!verification.verified || !verification.registrationInfo) {
    audit(userId, "security.passkey_registration_failed", { reason: "unverified" }, ip);
    throw unauthorized("Passkey registration could not be verified.", "INVALID_CREDENTIALS");
  }

  const info = verification.registrationInfo;
  const credential = info.credential;
  const deviceName = (requestedName?.trim() || "This device").slice(0, 60);
  const transports = credential.transports ?? response.response.transports ?? [];
  const createdAt = Date.now();
  try {
    db.prepare(
      "INSERT INTO webauthn_credentials " +
      "(id, user_id, credential_id, public_key, counter, transports, device_name, device_type, backed_up, created_at, last_used_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)"
    ).run(
      newId(), userId, credential.id, Buffer.from(credential.publicKey).toString("base64url"),
      credential.counter, JSON.stringify(transports), deviceName,
      info.credentialDeviceType, info.credentialBackedUp ? 1 : 0, createdAt,
    );
  } catch {
    audit(userId, "security.passkey_registration_failed", { reason: "credential_conflict" }, ip);
    throw conflict("This passkey is already registered. Use the existing credential or register a different device.", "CONFLICT");
  }
  audit(userId, "security.passkey_registered", { deviceName, deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp }, ip);
  return { credentialId: credential.id, deviceName, createdAt };
}

export async function createPasskeyLoginOptions(accountIdRaw: string): Promise<{
  challengeId: string;
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
}> {
  const accountId = normalizeAccountId(accountIdRaw);
  if (!isValidAccountId(accountId)) throw unauthorized("Passkey sign-in is unavailable. Use your account ID and password.", "INVALID_CREDENTIALS");
  const user = db.prepare("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL").get(accountId) as { id: string } | undefined;
  const credentials = user ? credentialDescriptors(user.id) : [];
  if (!user || credentials.length === 0) {
    audit(null, "security.passkey_login_unavailable", { reason: "no_credential_or_account" });
    throw unauthorized("Passkey sign-in is unavailable. Use your account ID and password.", "INVALID_CREDENTIALS");
  }
  const options = await generateAuthenticationOptions({
    rpID: config.WEBAUTHN_RP_ID,
    allowCredentials: credentials,
    userVerification: "required",
    timeout: CHALLENGE_TTL_MS,
  });
  const challengeId = saveChallenge(user.id, "login", options.challenge);
  return { challengeId, options };
}

export async function verifyPasskeyLogin(
  challengeId: string,
  response: AuthenticationResponseJSON,
  ip?: string,
): Promise<{ userId: string }> {
  const challenge = consumeChallenge(challengeId, "login");
  const credential = await verifyAssertionForChallenge(challenge, response, undefined, ip);
  return { userId: credential.user_id };
}

export async function createPasskeyPaymentOptions(userId: string, intent: PaymentIntent): Promise<{
  challengeId: string;
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
}> {
  const credentials = credentialDescriptors(userId);
  if (credentials.length === 0) throw badRequest("Enable a passkey in Settings before using device authentication for payments.", "BAD_REQUEST");
  const intentHash = getPaymentIntentHash(intent);
  const options = await generateAuthenticationOptions({
    rpID: config.WEBAUTHN_RP_ID,
    allowCredentials: credentials,
    userVerification: "required",
    timeout: CHALLENGE_TTL_MS,
  });
  const challengeId = saveChallenge(userId, "payment", options.challenge, intentHash);
  return { challengeId, options };
}

export async function verifyPasskeyPayment(
  userId: string,
  challengeId: string,
  response: AuthenticationResponseJSON,
  ip?: string,
): Promise<{ authorizationToken: string; expiresIn: number }> {
  const challenge = consumeChallenge(challengeId, "payment", userId);
  const credential = await verifyAssertionForChallenge(challenge, response, userId, ip);
  if (!challenge.intent_hash) throw unauthorized("This passkey challenge is not bound to a payment.", "PAYMENT_AUTH_REQUIRED");
  const authorization = issuePasskeyPaymentAuthorizationForIntent(userId, challenge.intent_hash, ip);
  audit(userId, "payment.passkey_authorized", { credentialId: credential.credential_id, expiresInSeconds: authorization.expiresIn }, ip);
  return authorization;
}

export function listPasskeys(userId: string): Array<{
  credentialId: string;
  deviceName: string;
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  transports: string[];
  createdAt: number;
  lastUsedAt: number | null;
}> {
  const rows = db.prepare(
    "SELECT credential_id, device_name, device_type, backed_up, transports, created_at, last_used_at " +
    "FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC"
  ).all(userId) as Array<{
    credential_id: string; device_name: string; device_type: "singleDevice" | "multiDevice";
    backed_up: number; transports: string; created_at: number; last_used_at: number | null;
  }>;
  return rows.map((row) => ({
    credentialId: row.credential_id,
    deviceName: row.device_name,
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    transports: JSON.parse(row.transports) as string[],
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  }));
}

export async function removePasskey(
  userId: string,
  credentialId: string,
  currentPassword: string,
  ip?: string,
): Promise<{ removed: true }> {
  const user = db.prepare("SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL").get(userId) as { password_hash: string } | undefined;
  if (!user || !(await verifyPassword(user.password_hash, currentPassword))) {
    throw unauthorized("Confirm your current account password before removing a passkey.", "INVALID_CREDENTIALS");
  }
  const result = db.prepare("DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?").run(userId, credentialId);
  if (result.changes !== 1) throw notFound("Passkey was not found for this account.");
  audit(userId, "security.passkey_removed", { credentialId }, ip);
  return { removed: true };
}
