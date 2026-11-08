// SPDX-License-Identifier: FSL-1.1-ALv2
// The federation inbox (spec 12.2): POST one envelope or control envelope as application/json, at most 1 MiB.
// The binding does step 0's transport part (size, content type, one strict I-JSON parse) and the optional RFC 9421
// request-signature check, then hands the parsed body to broker.acceptInbound, which runs the acceptance checks
// (spec 12.2.4: signature, typ, aud, expiry, replay, home broker, then the recipient's rules) and answers with a
// signed receipt or a plain refusal. Responses (spec 12.2.3):
//  - a plain refusal (the envelope could not be authenticated): the code's HTTP status and { error: { code, message } };
//  - accepted: 200 and { receipt };
//  - refused by the recipient's rules: the code's HTTP status and { error, receipt }; the code is the one generic
//    code the core chose for the sender and the message names no rule of the recipient's;
//  - 429 and 503 carry Retry-After, and so does a thread_state refusal of a reply that overtook the message it answers
//    (spec 9.3, 10.2); a duplicate of an accepted envelope gets 200 and the original receipt (core, step 5).
// A request signature, when present, never replaces any acceptance step.

import type { IncomingMessage, ServerResponse } from "node:http";
import { calculateJwkThumbprint } from "jose";
import { domainOf, isAddress } from "../core/address.ts";
import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import { FETCH_LIMITS, homeBroker, keyCompromisedSince } from "../core/domain.ts";
import type { DomainResolver, InboundContext, InboundResult } from "../core/interfaces.ts";
import type { SecurityEvent, SecurityEventName } from "../core/security-events.ts";
import type { BrokerEntry, DomainDocument, ErrorCode, Jwk } from "../core/types.ts";
import { isJsonContentType } from "./fetcher.ts";
import { verifyRequestSignature } from "./http-signatures.ts";
import type { RequestSignatureCheck } from "./http-signatures.ts";
import { parseStrictJsonBytes } from "./strict-json.ts";

/** HTTP status per error code (spec 18.3). `unreachable` is never an HTTP answer. */
export const HTTP_STATUS: Readonly<Record<ErrorCode, number>> = {
  invalid_input: 400,
  identity_mismatch: 403,
  unknown_scope: 422,
  unknown_type: 422,
  schema_invalid: 422,
  body_too_large: 413,
  no_relationship: 403,
  type_not_allowed: 403,
  not_disclosed: 403,
  org_policy: 403,
  federation_blocked: 403,
  client_not_allowed: 403,
  blocked: 403,
  dlp_blocked: 403,
  rate_limited: 429,
  thread_state: 409,
  needs_ratification: 409,
  unknown_recipient: 404,
  discovery_failed: 503,
  unreachable: 502,
  expired: 400,
  bad_envelope: 400,
  unsupported_version: 400,
  bad_signature: 401,
  wrong_audience: 400,
  replay: 409,
  broker_not_authorized: 403,
  not_accepted: 403,
  constraints_unsupported: 422,
  internal: 500,
};

/** Retry-After seconds the inbox sends with retryable answers. */
const RETRY_AFTER: Partial<Record<ErrorCode, number>> = { rate_limited: 60, discovery_failed: 60, internal: 30 };

/** Fixed messages for receipt refusals: they never describe the recipient's rules. */
const RECEIPT_MESSAGE = "refused by the recipient's broker";

export interface InboxBroker {
  readonly id: string;
  acceptInbound(envelope: unknown, ctx?: InboundContext): Promise<InboundResult>;
  recordSecurityEvent?(event: SecurityEventName, args?: { failed?: boolean; message?: string; details?: Omit<SecurityEvent["detail"], "event" | "broker"> }): Promise<void>;
}

/** One line of the inbox's own log (no envelope content). */
export interface InboxLogEntry {
  at: string;
  remote?: string;
  status: number;
  code?: ErrorCode;
  envelope_id?: string;
  type?: string;
  origin_broker?: string;
  receipt?: "accepted" | "refused";
  /** The optional RFC 9421 request signature: verified, absent, skipped (the sender isn't the home broker), invalid or ignored. */
  request_signature?: "verified" | "absent" | "skipped" | "invalid" | "ignored";
}

export type RequestSignatureMode = "verify" | "require" | "ignore";

export interface InboxOptions {
  broker: InboxBroker;
  /** This broker's inbox URL exactly as its domain document publishes it: @target-uri is rebuilt from it. */
  publicUrl: string;
  /** Optional RFC 9421 request signatures: verify when present (default), require, or ignore. */
  requestSignatures?: RequestSignatureMode;
  /** Finds the sending broker's pinned `http` keys. Without it, request signatures are ignored. */
  resolver?: DomainResolver;
  clock?: Clock;
  maxBodyBytes?: number;
  /** Requests per remote address per minute; beyond it, 429 with Retry-After. Default 600. */
  perRemotePerMinute?: number;
  onLog?: (entry: InboxLogEntry, req: IncomingMessage) => void;
}

class BodyTooLarge extends Error {}

/** Read and drop what is left of a request body, for at most `ms`. */
function drain(req: IncomingMessage, ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    if (req.complete) {
      resolve();
      return;
    }
    const done = (): void => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(done, ms);
    req.once("end", done);
    req.once("close", done);
    req.resume();
  });
}

function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > max) {
      reject(new BodyTooLarge());
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on("data", (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > max) {
        done = true;
        reject(new BodyTooLarge());
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    });
    req.on("error", (err) => {
      if (done) return;
      done = true;
      reject(err);
    });
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(text)),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  res.end(text);
}

function errorBody(code: ErrorCode, message: string): { error: { code: ErrorCode; message: string } } {
  return { error: { code, message } };
}

function retryAfter(code: ErrorCode): Record<string, string> {
  const s = RETRY_AFTER[code];
  return s === undefined ? {} : { "retry-after": String(s) };
}

/** The sending broker's pinned key with this kid and purpose, or null (unknown, unpinned, revoked, or another purpose). */
export async function pinnedKey(jwks: unknown, entry: BrokerEntry, doc: DomainDocument, kid: string, use: Jwk["alp_use"]): Promise<Jwk | null> {
  const keys = (jwks as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) return null;
  const k = (keys as Jwk[]).find((x) => x && typeof x === "object" && x.kid === kid);
  if (!k || k.alp_use !== use || !entry.jkt.includes(kid) || keyCompromisedSince(doc, kid) !== undefined) return null;
  try {
    const members = k.kty === "OKP" ? { kty: "OKP", crv: String(k.crv), x: String(k.x) } : { kty: "EC", crv: String(k.crv), x: String(k.x), y: String(k.y) };
    if ((await calculateJwkThumbprint(members, "sha256")) !== kid) return null;
  } catch {
    return null;
  }
  return k;
}

/** Small expiring set of used request-signature nonces. */
class NonceWindow {
  private readonly seen = new Map<string, number>();
  use(key: string, expiresSec: number, nowMs: number): boolean {
    if (this.seen.size > 10_000) for (const [k, until] of this.seen) if (until < nowMs) this.seen.delete(k);
    const until = this.seen.get(key);
    if (until !== undefined && until >= nowMs) return false;
    this.seen.set(key, (expiresSec + 60) * 1000);
    return true;
  }
}

/** Build the inbox request handler. Mount it before any body parser (it reads the raw bytes itself). */
export function createInboxHandler(opts: InboxOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const clock = opts.clock ?? systemClock;
  const maxBody = opts.maxBodyBytes ?? FETCH_LIMITS.envelopeMaxBytes;
  const mode: RequestSignatureMode = opts.resolver ? (opts.requestSignatures ?? "verify") : "ignore";
  const perMinute = opts.perRemotePerMinute ?? 600;
  const windows = new Map<string, { start: number; count: number }>();
  const nonces = new NonceWindow();

  const allowRemote = (remote: string): boolean => {
    const now = Date.now();
    const w = windows.get(remote);
    if (!w || now - w.start >= 60_000) {
      if (windows.size > 10_000) windows.clear();
      windows.set(remote, { start: now, count: 1 });
      return true;
    }
    w.count++;
    return w.count <= perMinute;
  };

  const event = async (name: SecurityEventName, code: ErrorCode, origin?: string): Promise<void> => {
    const safeOrigin = origin && /^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/.test(origin) ? { origin_broker: origin } : {};
    await opts.broker.recordSecurityEvent?.(name, { failed: true, details: { code, ...safeOrigin } });
  };

  const checkSignature = async (req: IncomingMessage, bytes: Buffer, parsed: unknown, remote: string): Promise<RequestSignatureCheck | { status: "skipped" | "ignored" }> => {
    if (mode === "ignore" || !opts.resolver) return { status: "ignored" };
    if (req.headers["signature-input"] === undefined && req.headers["signature"] === undefined) return { status: "absent" };
    const p = parsed as { from?: { address?: unknown }; origin_broker?: unknown } | null;
    const from = p?.from?.address;
    const origin = p?.origin_broker;
    if (!isAddress(from) || typeof origin !== "string") return { status: "skipped" };
    // The keys come from the signing broker's entry in the sender domain's document. If that broker is not the
    // sender's home broker, the request signature can't be checked; acceptInbound refuses the envelope anyway.
    // Discovery of a never-seen domain is charged to this requester's budget (spec 4.3 rule 6), as acceptInbound's
    // own lookup is: junk requests can't spend the allowance this broker's own sends use.
    let doc: DomainDocument;
    let entry: BrokerEntry | undefined;
    try {
      doc = await opts.resolver.domainDocument(domainOf(from), { budget: remote });
      entry = homeBroker(doc, from);
    } catch {
      return { status: "skipped" };
    }
    if (!entry || entry.id !== origin) return { status: "skipped" };
    const home = entry;
    const resolver = opts.resolver;
    return verifyRequestSignature(
      { method: req.method ?? "POST", targetUri: opts.publicUrl, headers: req.headers },
      {
        body: bytes,
        now: clock.now(),
        keyFor: async (kid) => {
          try {
            return await pinnedKey(await resolver.jwks(home.jwks_uri), home, doc, kid, "http");
          } catch {
            return null;
          }
        },
        useNonce: (nonce, expires) => nonces.use(`${origin}|${nonce}`, expires, clock.now().getTime()),
      },
    );
  };

  return async (req, res) => {
    const remote = req.socket.remoteAddress ?? "unknown";
    const entry: InboxLogEntry = { at: clock.now().toISOString(), remote, status: 0 };
    const reply = (status: number, body: unknown, headers: Record<string, string> = {}): void => {
      entry.status = status;
      sendJson(res, status, body, headers);
      opts.onLog?.(entry, req);
    };
    try {
      if (req.method !== "POST") return reply(405, errorBody("invalid_input", "the inbox takes POST"), { allow: "POST" });
      if (!allowRemote(remote)) {
        entry.code = "rate_limited";
        return reply(429, errorBody("rate_limited", "too many requests"), { "retry-after": "60" });
      }
      if (!isJsonContentType(req.headers["content-type"])) {
        entry.code = "bad_envelope";
        return reply(415, errorBody("bad_envelope", "the inbox takes application/json"));
      }
      let bytes: Buffer;
      try {
        bytes = await readBody(req, maxBody);
      } catch (err) {
        if (!(err instanceof BodyTooLarge)) throw err;
        entry.code = "bad_envelope";
        await event("envelope_refused", "bad_envelope");
        // The rest of the body is drained and dropped (for at most 5 seconds) before the answer, so the sender reads
        // the 413 instead of a connection reset while it is still writing.
        await drain(req, 5000);
        return reply(413, errorBody("bad_envelope", "the envelope is over 1 MiB"), { connection: "close" });
      }
      let parsed: unknown;
      try {
        parsed = parseStrictJsonBytes(bytes);
      } catch {
        entry.code = "bad_envelope";
        await event("envelope_refused", "bad_envelope");
        return reply(400, errorBody("bad_envelope", "the body is not one strict I-JSON text"));
      }
      const p = parsed as { id?: unknown; type?: unknown; origin_broker?: unknown } | null;
      if (p && typeof p === "object") {
        if (typeof p.id === "string") entry.envelope_id = p.id.slice(0, 64);
        if (typeof p.type === "string") entry.type = p.type.slice(0, 32);
        if (typeof p.origin_broker === "string") entry.origin_broker = p.origin_broker.slice(0, 256);
      }

      const sig = await checkSignature(req, bytes, parsed, remote);
      entry.request_signature = sig.status;
      if (sig.status === "invalid" || (sig.status === "absent" && mode === "require")) {
        entry.code = "bad_signature";
        await event("signature_failure", "bad_signature", entry.origin_broker);
        return reply(401, errorBody("bad_signature", sig.status === "absent" ? "this inbox requires a request signature" : "the request signature did not verify"));
      }

      const result = await opts.broker.acceptInbound(parsed, { remote });
      if (result.kind === "refused") {
        entry.code = result.code;
        // A duplicate that arrived while the first copy is still being evaluated: 503 with a short Retry-After.
        if (result.retry_after !== undefined) return reply(result.status, errorBody(result.code, result.message), { "retry-after": String(result.retry_after) });
        return reply(HTTP_STATUS[result.code] ?? result.status, errorBody(result.code, result.message), retryAfter(result.code));
      }
      const receipt = result.receipt;
      entry.receipt = receipt.status;
      if (receipt.status === "accepted") return reply(200, { receipt });
      const code = receipt.code ?? "not_accepted";
      entry.code = code;
      return reply(HTTP_STATUS[code] ?? 403, { ...errorBody(code, RECEIPT_MESSAGE), receipt }, result.retry_after !== undefined ? { "retry-after": String(result.retry_after) } : retryAfter(code));
    } catch {
      // Never echo internal errors.
      entry.code = "internal";
      if (!res.headersSent) reply(500, errorBody("internal", "internal error"), retryAfter("internal"));
    }
  };
}
