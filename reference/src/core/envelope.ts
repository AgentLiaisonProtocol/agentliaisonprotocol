// SPDX-License-Identifier: FSL-1.1-ALv2
// Signing and checking the four cross-broker objects. Each is a broker-signed detached JWS over its JCS content
// with its own typ (spec 8.1), and each is validated with the spec's own schema.

import { hashJson } from "./hash.ts";
import { canonicalBytes } from "./jcs.ts";
import { ALP_VERSION } from "./protocol.ts";
import { JWS_TYP, signDetached, verifyDetached } from "./jws.ts";
import type { JwsTyp, VerifyResult } from "./jws.ts";
import type { KeyRing } from "./keys.ts";
import { assertValid } from "./spec-schemas.ts";
import { isControlType, isMessageType } from "./types.ts";
import type {
  AnyEnvelope,
  ControlEnvelope,
  Envelope,
  Jwks,
  Ratification,
  Receipt,
  Sha256,
  UnsignedControlEnvelope,
  UnsignedEnvelope,
  UnsignedRatification,
  UnsignedReceipt,
} from "./types.ts";

type Signed = { broker_sig: string };

function strip<T extends Signed>(o: T): Omit<T, "broker_sig"> {
  const { broker_sig: _sig, ...rest } = o;
  return rest;
}

async function sign<U extends object>(u: U, typ: JwsTyp, ring: KeyRing): Promise<U & Signed> {
  const { broker_sig: _old, ...unsigned } = u as U & Partial<Signed>;
  return { ...(unsigned as U), broker_sig: await signDetached(unsigned, typ, ring) };
}

export const signEnvelope = (u: UnsignedEnvelope, ring: KeyRing): Promise<Envelope> => sign(u, JWS_TYP.envelope, ring);
export const signControl = (u: UnsignedControlEnvelope, ring: KeyRing): Promise<ControlEnvelope> => sign(u, JWS_TYP.control, ring);
export const signReceipt = (u: UnsignedReceipt, ring: KeyRing): Promise<Receipt> => sign(u, JWS_TYP.receipt, ring);
export const signRatification = (u: UnsignedRatification, ring: KeyRing): Promise<Ratification> => sign(u, JWS_TYP.ratification, ring);

export function typOf(e: AnyEnvelope): JwsTyp {
  return isControlType(e.type) ? JWS_TYP.control : JWS_TYP.envelope;
}

/** Verify any envelope with the typ its type requires (a control message can never pass as a message, or back). */
export function verifyAnyEnvelope(e: AnyEnvelope, jwks: Jwks): Promise<VerifyResult> {
  return verifyDetached(strip(e), e.broker_sig, typOf(e), jwks);
}
export const verifyReceipt = (r: Receipt, jwks: Jwks): Promise<VerifyResult> => verifyDetached(strip(r), r.broker_sig, JWS_TYP.receipt, jwks);
export const verifyRatification = (r: Ratification, jwks: Jwks): Promise<VerifyResult> => verifyDetached(strip(r), r.broker_sig, JWS_TYP.ratification, jwks);

/** Structural check of anything arriving at a federation inbox. Throws `bad_envelope`. */
export function checkAnyEnvelope(value: unknown): AnyEnvelope {
  const type = value && typeof value === "object" ? (value as { type?: unknown }).type : undefined;
  return isControlType(type) ? assertValid<ControlEnvelope>("control", value, "bad_envelope") : assertValid<Envelope>("envelope", value, "bad_envelope");
}

export interface StructureLimits {
  /** expires_at is at most this long after created_at (7 days). */
  maxTtlSeconds: number;
  /** created_at is at most this far ahead of the receiving broker's clock (300 seconds). */
  clockSkewSeconds: number;
  /** The body's JCS form (64 KiB). */
  bodyMaxBytes: number;
}

export const STRUCTURE_LIMITS: StructureLimits = { maxTtlSeconds: 7 * 24 * 3600, clockSkewSeconds: 300, bodyMaxBytes: 64 * 1024 };

export type StructureResult = { ok: true; envelope: AnyEnvelope; typ: JwsTyp } | { ok: false; code: "bad_envelope" | "unsupported_version" | "body_too_large"; detail: string };

/**
 * Acceptance step 0 (spec 12.2.4) on an object already parsed once with a strict parser: the version, the shape
 * (message or control type) selects the schema and the object passes it, `expires_at` is after `created_at` and at
 * most 7 days later, and, when `now` is given, `created_at` is at most 300 seconds ahead of the broker's clock.
 */
export function checkEnvelopeStructure(value: unknown, now?: Date, limits: StructureLimits = STRUCTURE_LIMITS): StructureResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { ok: false, code: "bad_envelope", detail: "not a JSON object" };
  if ((value as { alp?: unknown }).alp !== ALP_VERSION) return { ok: false, code: "unsupported_version", detail: "unknown protocol version" };
  const type = (value as { type?: unknown }).type;
  if (!isControlType(type) && !isMessageType(type)) return { ok: false, code: "bad_envelope", detail: "unknown type" };
  let env: AnyEnvelope;
  try {
    env = checkAnyEnvelope(value);
  } catch (err) {
    return { ok: false, code: "bad_envelope", detail: err instanceof Error ? err.message : "fails the schema" };
  }
  const created = Date.parse(env.created_at);
  const expires = Date.parse(env.expires_at);
  if (!(expires > created)) return { ok: false, code: "bad_envelope", detail: "expires_at is not after created_at" };
  if (expires - created > limits.maxTtlSeconds * 1000) return { ok: false, code: "bad_envelope", detail: "expires_at is more than 7 days after created_at" };
  if (now && created > now.getTime() + limits.clockSkewSeconds * 1000) return { ok: false, code: "bad_envelope", detail: "created_at is in the future" };
  if (canonicalBytes(env.body).byteLength > limits.bodyMaxBytes) return { ok: false, code: "body_too_large", detail: "the body is over 64 KiB" };
  return { ok: true, envelope: env, typ: typOf(env) };
}
export const checkReceipt = (v: unknown): Receipt => assertValid<Receipt>("receipt", v, "bad_envelope");
export const checkRatification = (v: unknown): Ratification => assertValid<Ratification>("ratification", v, "bad_envelope");

/** Hash of a whole signed object (both ledgers record the same value). */
export function objectHash(o: AnyEnvelope | Receipt | Ratification): Sha256 {
  return hashJson(o);
}
