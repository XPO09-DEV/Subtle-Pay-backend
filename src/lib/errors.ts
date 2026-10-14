import type { FastifyError, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";

export type ErrorCode =
  | "BAD_REQUEST" | "VALIDATION_ERROR" | "INVALID_AMOUNT" | "INVALID_CURRENCY" | "INVALID_ACCOUNT_ID"
  | "UNAUTHORIZED" | "INVALID_CREDENTIALS" | "TOKEN_EXPIRED" | "TOKEN_REUSED" | "FORBIDDEN" | "NOT_FOUND"
  | "ROUTE_NOT_FOUND" | "ALIAS_NOT_FOUND" | "CONFLICT" | "ALIAS_TAKEN" | "IDEMPOTENCY_CONFLICT"
  | "PAYLOAD_TOO_LARGE" | "UNSUPPORTED_MEDIA_TYPE" | "INSUFFICIENT_FUNDS" | "LIMIT_EXCEEDED"
  | "SELF_PAYMENT" | "RATE_LIMITED" | "ACCOUNT_LOCKED" | "INTERNAL" | "CHAIN_UNAVAILABLE" | "RATES_UNAVAILABLE"
  | "INVALID_MPIN" | "MPIN_NOT_SET" | "INVALID_COUNTRY" | "ALIAS_RESERVED" | "PAYMENT_AUTH_REQUIRED" | "ALIAS_IMMUTABLE"
  | "MERCHANT_REQUIRED" | "APPLICATION_PENDING" | "CURRENT_SESSION";

export interface ErrorDetail { path: string; message: string; }
interface AppErrorOptions { details?: unknown; headers?: Record<string, string>; cause?: unknown; }
export class AppError extends Error {
  readonly details?: unknown;
  readonly headers?: Record<string, string>;
  constructor(public readonly statusCode: number, public readonly code: ErrorCode, message: string, options: AppErrorOptions = {}) {
    super(message, { cause: options.cause });
    this.name = "AppError"; this.details = options.details; this.headers = options.headers;
  }
}
export const badRequest = (message: string, code: ErrorCode = "BAD_REQUEST") => new AppError(400, code, message);
export const unauthorized = (message = "Authentication required", code: ErrorCode = "UNAUTHORIZED") => new AppError(401, code, message);
export const invalidCredentials = () => new AppError(401, "INVALID_CREDENTIALS", "Invalid account ID or password");
export const forbidden = (message = "You do not have access to this") => new AppError(403, "FORBIDDEN", message);
export const notFound = (message = "Not found", code: ErrorCode = "NOT_FOUND") => new AppError(404, code, message);
export const conflict = (message: string, code: ErrorCode = "CONFLICT") => new AppError(409, code, message);
export const unprocessable = (message: string, code: ErrorCode) => new AppError(422, code, message);
export const insufficientFunds = () => unprocessable("Insufficient balance for this payment", "INSUFFICIENT_FUNDS");
export const tooManyRequests = (retryAfterSeconds: number, message = "Too many requests") =>
  new AppError(429, "RATE_LIMITED", message, { headers: { "Retry-After": String(Math.max(1, Math.ceil(retryAfterSeconds))) } });
export const accountLocked = (retryAfterSeconds: number) => new AppError(429, "ACCOUNT_LOCKED", "Too many failed attempts. Try again later.", { headers: { "Retry-After": String(Math.max(1, Math.ceil(retryAfterSeconds))) } });
export const serviceUnavailable = (message: string, code: ErrorCode = "CHAIN_UNAVAILABLE", cause?: unknown) =>
  new AppError(503, code, message, { cause });

interface Normalized { status: number; code: ErrorCode; message: string; details?: unknown; headers?: Record<string, string>; }
const SAFE_MESSAGES: Record<number, string> = {
  400: "Bad request", 401: "Authentication required", 403: "Forbidden", 404: "Not found",
  413: "Request body too large", 415: "Unsupported media type", 429: "Too many requests",
};
function codeForStatus(status: number): ErrorCode {
  switch (status) {
    case 401: return "UNAUTHORIZED"; case 403: return "FORBIDDEN"; case 404: return "NOT_FOUND";
    case 413: return "PAYLOAD_TOO_LARGE"; case 415: return "UNSUPPORTED_MEDIA_TYPE";
    case 429: return "RATE_LIMITED"; default: return "BAD_REQUEST";
  }
}
function asFastifyError(err: unknown): Partial<FastifyError> {
  return typeof err === "object" && err !== null ? err as Partial<FastifyError> : {};
}
function normalize(err: unknown): Normalized {
  if (err instanceof AppError) return { status: err.statusCode, code: err.code, message: err.message, details: err.details, headers: err.headers };
  if (err instanceof ZodError) return {
    status: 400, code: "VALIDATION_ERROR", message: "Some fields are invalid",
    details: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
  };
  const fe = asFastifyError(err);
  if (fe.validation) return {
    status: 400, code: "VALIDATION_ERROR", message: "Some fields are invalid",
    details: fe.validation.map((v) => ({ path: (v.instancePath ?? "").replace(/^\//, "").replace(/\//g, "."), message: v.message ?? "Invalid value" })),
  };
  if (typeof fe.code === "string" && fe.code.startsWith("FST_JWT_")) {
    const expired = fe.code === "FST_JWT_AUTHORIZATION_TOKEN_EXPIRED";
    return { status: 401, code: expired ? "TOKEN_EXPIRED" : "UNAUTHORIZED", message: expired ? "Session expired" : "Invalid or missing token" };
  }
  const status = fe.statusCode;
  if (typeof status === "number" && status >= 400 && status < 500) return { status, code: codeForStatus(status), message: SAFE_MESSAGES[status] ?? "Bad request" };
  return { status: 500, code: "INTERNAL", message: "Something went wrong" };
}

export function errorHandler(err: unknown, req: FastifyRequest, reply: FastifyReply) {
  const n = normalize(err);
  // Do not serialize exception objects: they may contain provider URLs, SQL parameters or request data.
  if (n.status >= 500) req.log.error({ requestId: req.id, code: n.code, status: n.status, method: req.method }, "request failed");
  else req.log.debug({ requestId: req.id, code: n.code, status: n.status, method: req.method }, "request rejected");
  if (n.headers) reply.headers(n.headers);
  const body: Record<string, unknown> = { code: n.code, message: n.message, requestId: req.id };
  if (n.details !== undefined) body.details = n.details;
  return reply.status(n.status).send({ error: body });
}
export function notFoundHandler(req: FastifyRequest, reply: FastifyReply) {
  return reply.status(404).send({ error: { code: "ROUTE_NOT_FOUND", message: "Route not found", requestId: req.id } });
}
