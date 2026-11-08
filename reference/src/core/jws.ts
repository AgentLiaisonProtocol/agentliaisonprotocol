// SPDX-License-Identifier: FSL-1.1-ALv2
// Detached JWS (RFC 7515 Appendix F) over the RFC 8785 canonical form of an object.
// Compact serialization with an empty payload segment: `<protected header>..<signature>`.
// Spec 8.5 and 8.7: the protected header has exactly `alg`, `kid` and `typ`; any other member (jku, x5u, jwk, x5c,
// crit...) makes the object invalid and is never used to find a key. The algorithm comes from the key, never from
// the message. Verification: Ed25519 (RFC 9864) and ES256 (spec 8.8: both MUST verify); signing: Ed25519.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { JsonWebKey, KeyObject } from "node:crypto";
import { CompactSign } from "jose";
import { canonicalBytes } from "./jcs.ts";
import { base64url } from "./hash.ts";
import { JWS_ALG } from "./keys.ts";
import type { KeyRing } from "./keys.ts";
import { PROTOCOL } from "./protocol.ts";
import type { Jwk, Jwks } from "./types.ts";

const T = PROTOCOL.typPrefix;
/** One typ per kind of signed object, so one can never be accepted as another (spec 8.1). */
export const JWS_TYP = {
  envelope: `${T}envelope+jws`,
  control: `${T}control+jws`,
  receipt: `${T}receipt+jws`,
  ratification: `${T}ratification+jws`,
  grant: `${T}grant+jws`,
  ledgerExport: `${T}ledger+jws`,
} as const;
export type JwsTyp = (typeof JWS_TYP)[keyof typeof JWS_TYP];

/**
 * Failures in the order the checks run: the header's shape (`malformed`), the key (`unknown_kid`, `bad_key`), the
 * algorithm (`bad_alg`), the signature (`invalid`), then the typ (`wrong_typ`, acceptance step 2).
 */
export type VerifyFailure = "malformed" | "wrong_typ" | "bad_alg" | "unknown_kid" | "bad_key" | "invalid";
export type VerifyResult = { ok: true; kid: string; alg: string } | { ok: false; failure: VerifyFailure };

/** The algorithms a verifier accepts (spec 8.8). */
export const VERIFY_ALGS = ["Ed25519", "ES256"] as const;

export async function signDetached(content: unknown, typ: JwsTyp, ring: KeyRing): Promise<string> {
  const key = ring.active();
  const jws = await new CompactSign(canonicalBytes(content))
    .setProtectedHeader({ alg: JWS_ALG, kid: key.kid, typ })
    .sign(ring.privateKey(key.kid));
  const [header, , signature] = jws.split(".");
  return `${header}..${signature}`;
}

function decodeHeader(segment: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Read the key id of a detached JWS without verifying it (for key lookups). */
export function jwsKid(sig: string): string | null {
  const header = decodeHeader(String(sig).split(".")[0] ?? "");
  return header && typeof header["kid"] === "string" ? header["kid"] : null;
}

/** Read the typ of a detached JWS without verifying it. */
export function jwsTyp(sig: string): string | null {
  const header = decodeHeader(String(sig).split(".")[0] ?? "");
  return header && typeof header["typ"] === "string" ? header["typ"] : null;
}

/** The algorithm a public key signs with, from the key alone: Ed25519 (OKP) or ES256 (EC P-256). */
export function keyAlgorithm(jwk: Jwk): "Ed25519" | "ES256" | null {
  if (jwk.d !== undefined) return null;
  let alg: "Ed25519" | "ES256" | null = null;
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") alg = "Ed25519";
  if (jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string") alg = "ES256";
  if (alg && jwk.alg !== undefined && jwk.alg !== alg) return null;
  return alg;
}

function publicKeyOf(jwk: Jwk, alg: "Ed25519" | "ES256"): KeyObject {
  const pub: JsonWebKey = alg === "Ed25519" ? { kty: "OKP", crv: "Ed25519", x: String(jwk.x) } : { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) };
  return createPublicKey({ key: pub, format: "jwk" });
}

export async function verifyDetached(content: unknown, sig: string, typ: JwsTyp, jwks: Jwks): Promise<VerifyResult> {
  if (typeof sig !== "string") return { ok: false, failure: "malformed" };
  const parts = sig.split(".");
  if (parts.length !== 3 || parts[1] !== "" || !parts[0] || !parts[2]) return { ok: false, failure: "malformed" };
  const header = decodeHeader(parts[0]);
  if (!header) return { ok: false, failure: "malformed" };
  // Exactly alg, kid and typ. jku, x5u, jwk, x5c, crit, b64 and anything else make the object invalid.
  const members = Object.keys(header).sort();
  if (members.length !== 3 || members[0] !== "alg" || members[1] !== "kid" || members[2] !== "typ") return { ok: false, failure: "malformed" };
  if (typeof header["alg"] !== "string" || typeof header["kid"] !== "string" || typeof header["typ"] !== "string") return { ok: false, failure: "malformed" };
  const kid = header["kid"];
  // Keys come only from the JWKS the caller trusts (pinned by the domain document, or the broker's own).
  const jwk: Jwk | undefined = jwks?.keys?.find((k) => k.kid === kid);
  if (!jwk) return { ok: false, failure: "unknown_kid" };
  const keyAlg = keyAlgorithm(jwk);
  if (!keyAlg) return { ok: false, failure: "bad_key" };
  if (header["alg"] !== keyAlg) return { ok: false, failure: "bad_alg" };
  let key: KeyObject;
  try {
    key = publicKeyOf(jwk, keyAlg);
  } catch {
    return { ok: false, failure: "bad_key" };
  }
  let payload: string;
  try {
    payload = base64url(canonicalBytes(content));
  } catch {
    return { ok: false, failure: "malformed" };
  }
  const input = Buffer.from(`${parts[0]}.${payload}`, "ascii");
  const signature = Buffer.from(parts[2], "base64url");
  let good = false;
  try {
    good = keyAlg === "Ed25519" ? cryptoVerify(null, input, key, signature) : signature.length === 64 && cryptoVerify("sha256", input, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    good = false;
  }
  if (!good) return { ok: false, failure: "invalid" };
  if (header["typ"] !== typ) return { ok: false, failure: "wrong_typ" };
  return { ok: true, kid, alg: keyAlg };
}
