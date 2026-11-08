// SPDX-License-Identifier: FSL-1.1-ALv2
// HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530): the subset the federation binding's optional
// request-signature profile uses (spec 12.2.2). A sender's broker MAY sign its POST to a federation inbox; if it
// does, it covers `@method`, `@target-uri`, `content-type` and `content-digest`, with the parameters `created`,
// `expires` (at most 300 seconds after `created`), `nonce`, `keyid` (a key with `alp_use: http`) and the profile tag.
// A request signature never replaces any acceptance step: the signed envelope stays the authentication.
//
// Implemented here (and tested against RFC 9421's own Ed25519 vector, B.2.6): the derived components @method,
// @target-uri, @authority, @scheme, @request-target, @path and @query; header-field components without parameters;
// the signature base; Ed25519 signing; Ed25519 and ecdsa-p256-sha256 verification; RFC 8941 dictionaries, inner lists,
// strings, tokens, integers, booleans and byte sequences. Not implemented (not used by the profile): component
// parameters (;sf ;key ;bs ;req ;tr), @query-param, @status, response signatures, decimals, and HMAC/RSA algorithms.
// No maintained RFC 9421 library was adopted (ARCHITECTURE.md: http-message-signatures was dropped).

import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { PROTOCOL } from "../core/protocol.ts";
import type { Jwk } from "../core/types.ts";

/** The federation profile (spec 12.2.2). The tag and label derive from the protocol id. */
export const FEDERATION_SIGNATURE_PROFILE = {
  label: PROTOCOL.id,
  tag: `${PROTOCOL.typPrefix}fed`,
  components: ["@method", "@target-uri", "content-type", "content-digest"] as readonly string[],
  maxLifetimeSeconds: 300,
  clockSkewSeconds: 60,
} as const;

// ---------------------------------------------------------------------------------------------
// RFC 8941 structured fields (the subset needed for Signature-Input, Signature and Content-Digest)

export type BareItem = string | number | boolean | Uint8Array | { token: string };
export type SfParams = Map<string, BareItem>;
export interface SfItem {
  kind: "item";
  value: BareItem;
  params: SfParams;
}
export interface SfInnerList {
  kind: "list";
  items: SfItem[];
  params: SfParams;
}
export type SfMember = SfItem | SfInnerList;

export class StructuredFieldError extends Error {
  constructor(message: string) {
    super(`structured field: ${message}`);
    this.name = "StructuredFieldError";
  }
}

class SfParser {
  private i = 0;
  private readonly s: string;
  constructor(s: string) {
    this.s = s;
  }

  dictionary(): Map<string, SfMember> {
    const out = new Map<string, SfMember>();
    this.skipSp();
    if (this.i === this.s.length) return out;
    for (;;) {
      const key = this.key();
      if (this.s[this.i] === "=") {
        this.i++;
        out.set(key, this.s[this.i] === "(" ? this.innerList() : this.item());
      } else {
        out.set(key, { kind: "item", value: true, params: this.params() });
      }
      this.skipOws();
      if (this.i === this.s.length) return out;
      if (this.s[this.i] !== ",") throw new StructuredFieldError(`expected ',' at ${this.i}`);
      this.i++;
      this.skipOws();
      if (this.i === this.s.length) throw new StructuredFieldError("trailing comma");
    }
  }

  private innerList(): SfInnerList {
    this.i++; // (
    const items: SfItem[] = [];
    for (;;) {
      while (this.s[this.i] === " ") this.i++;
      if (this.s[this.i] === ")") {
        this.i++;
        return { kind: "list", items, params: this.params() };
      }
      items.push(this.item());
      const c = this.s[this.i];
      if (c !== " " && c !== ")") throw new StructuredFieldError(`expected ' ' or ')' at ${this.i}`);
    }
  }

  private item(): SfItem {
    return { kind: "item", value: this.bareItem(), params: this.params() };
  }

  private params(): SfParams {
    const out: SfParams = new Map();
    while (this.s[this.i] === ";") {
      this.i++;
      while (this.s[this.i] === " ") this.i++;
      const key = this.key();
      let value: BareItem = true;
      if (this.s[this.i] === "=") {
        this.i++;
        value = this.bareItem();
      }
      out.set(key, value);
    }
    return out;
  }

  private key(): string {
    const m = /[a-z*][a-z0-9_\-.*]*/y;
    m.lastIndex = this.i;
    const r = m.exec(this.s);
    if (!r) throw new StructuredFieldError(`expected a key at ${this.i}`);
    this.i += r[0].length;
    return r[0];
  }

  private bareItem(): BareItem {
    const c = this.s[this.i];
    if (c === '"') return this.string();
    if (c === ":") return this.bytes();
    if (c === "?") {
      const b = this.s[this.i + 1];
      if (b !== "0" && b !== "1") throw new StructuredFieldError("bad boolean");
      this.i += 2;
      return b === "1";
    }
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) {
      const m = /-?[0-9]{1,15}(?![0-9.])/y;
      m.lastIndex = this.i;
      const r = m.exec(this.s);
      if (!r) throw new StructuredFieldError(`unsupported number at ${this.i}`);
      this.i += r[0].length;
      return Number(r[0]);
    }
    const t = /[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*/y;
    t.lastIndex = this.i;
    const r = t.exec(this.s);
    if (!r) throw new StructuredFieldError(`unexpected character at ${this.i}`);
    this.i += r[0].length;
    return { token: r[0] };
  }

  private string(): string {
    this.i++; // "
    let out = "";
    for (;;) {
      const c = this.s[this.i++];
      if (c === undefined) throw new StructuredFieldError("unterminated string");
      if (c === '"') return out;
      if (c === "\\") {
        const n = this.s[this.i++];
        if (n !== '"' && n !== "\\") throw new StructuredFieldError("bad escape");
        out += n;
        continue;
      }
      const code = c.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new StructuredFieldError("non-printable character in a string");
      out += c;
    }
  }

  private bytes(): Uint8Array {
    const end = this.s.indexOf(":", this.i + 1);
    if (end < 0) throw new StructuredFieldError("unterminated byte sequence");
    const b64 = this.s.slice(this.i + 1, end);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new StructuredFieldError("bad base64 in a byte sequence");
    this.i = end + 1;
    return new Uint8Array(Buffer.from(b64, "base64"));
  }

  private skipSp(): void {
    while (this.s[this.i] === " ") this.i++;
  }

  private skipOws(): void {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++;
  }
}

export function parseDictionary(value: string): Map<string, SfMember> {
  return new SfParser(value.trim()).dictionary();
}

function serializeBareItem(v: BareItem): string {
  if (typeof v === "string") {
    if (!/^[\x20-\x7e]*$/.test(v)) throw new StructuredFieldError("strings must be printable ASCII");
    return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > 999_999_999_999_999) throw new StructuredFieldError("integers only");
    return String(v);
  }
  if (typeof v === "boolean") return v ? "?1" : "?0";
  if (v instanceof Uint8Array) return `:${Buffer.from(v).toString("base64")}:`;
  return v.token;
}

function serializeParams(params: SfParams | [string, BareItem][]): string {
  let out = "";
  for (const [k, v] of params) out += v === true ? `;${k}` : `;${k}=${serializeBareItem(v)}`;
  return out;
}

/** The inner list of covered components with its parameters: the `@signature-params` value. */
export function serializeSignatureParams(components: readonly string[], params: [string, BareItem][]): string {
  return `(${components.map((c) => serializeBareItem(c)).join(" ")})${serializeParams(params)}`;
}

// ---------------------------------------------------------------------------------------------
// Content-Digest (RFC 9530)

const DIGESTS = { "sha-256": "sha256", "sha-512": "sha512" } as const;
type DigestAlg = keyof typeof DIGESTS;

export function contentDigest(body: Uint8Array, alg: DigestAlg = "sha-256"): string {
  return `${alg}=:${createHash(DIGESTS[alg]).update(body).digest("base64")}:`;
}

/** True when the header has at least one supported digest and every supported digest in it matches the body. */
export function checkContentDigest(header: string | undefined, body: Uint8Array): boolean {
  if (!header) return false;
  let dict: Map<string, SfMember>;
  try {
    dict = parseDictionary(header);
  } catch {
    return false;
  }
  let checked = 0;
  for (const [alg, member] of dict) {
    if (!(alg in DIGESTS)) continue;
    if (member.kind !== "item" || !(member.value instanceof Uint8Array)) return false;
    const expected = createHash(DIGESTS[alg as DigestAlg]).update(body).digest();
    if (!expected.equals(Buffer.from(member.value))) return false;
    checked++;
  }
  return checked > 0;
}

// ---------------------------------------------------------------------------------------------
// Components and the signature base (RFC 9421 Sections 2.1 to 2.5)

export interface SignableRequest {
  method: string;
  /** The target URI: what the signer sends to; what the verifier rebuilds from its published inbox URL. */
  targetUri: string;
  /** Header fields, any case. */
  headers: Record<string, string | string[] | undefined>;
}

function headerValue(headers: SignableRequest["headers"], name: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== name) continue;
    if (v === undefined) return undefined;
    const values = Array.isArray(v) ? v : [v];
    return values.map((x) => x.trim()).join(", ");
  }
  return undefined;
}

export function componentValue(name: string, req: SignableRequest): string {
  if (name.startsWith("@")) {
    const u = new URL(req.targetUri);
    switch (name) {
      case "@method":
        return req.method;
      case "@target-uri":
        return req.targetUri;
      case "@authority":
        return u.host.toLowerCase();
      case "@scheme":
        return u.protocol.slice(0, -1).toLowerCase();
      case "@request-target":
        return `${u.pathname || "/"}${u.search}`;
      case "@path":
        return u.pathname || "/";
      case "@query":
        return u.search || "?";
      default:
        throw new StructuredFieldError(`unsupported derived component ${name}`);
    }
  }
  if (name !== name.toLowerCase()) throw new StructuredFieldError("component names are lower case");
  const v = headerValue(req.headers, name);
  if (v === undefined) throw new StructuredFieldError(`the message has no ${name} field`);
  return v;
}

export function signatureBase(req: SignableRequest, components: readonly string[], params: [string, BareItem][]): string {
  if (new Set(components).size !== components.length) throw new StructuredFieldError("a component is listed twice");
  const lines = components.map((c) => `${serializeBareItem(c)}: ${componentValue(c, req)}`);
  lines.push(`"@signature-params": ${serializeSignatureParams(components, params)}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Signing and verifying

export interface SigningKey {
  kid: string;
  /** An Ed25519 private key. */
  privateKey: KeyObject;
}

export interface SignOptions {
  created: number;
  expires: number;
  nonce: string;
  tag?: string;
  label?: string;
  components?: readonly string[];
}

/** Sign a request; returns the Signature-Input and Signature field values to add. */
export function signRequest(req: SignableRequest, key: SigningKey, opts: SignOptions): { "signature-input": string; signature: string } {
  if (key.privateKey.asymmetricKeyType !== "ed25519") throw new Error("request signing uses Ed25519 keys");
  const label = opts.label ?? FEDERATION_SIGNATURE_PROFILE.label;
  const components = opts.components ?? FEDERATION_SIGNATURE_PROFILE.components;
  const params: [string, BareItem][] = [
    ["created", opts.created],
    ["expires", opts.expires],
    ["nonce", opts.nonce],
    ["keyid", key.kid],
    ["tag", opts.tag ?? FEDERATION_SIGNATURE_PROFILE.tag],
  ];
  const base = signatureBase(req, components, params);
  const sig = cryptoSign(null, Buffer.from(base, "utf8"), key.privateKey);
  return { "signature-input": `${label}=${serializeSignatureParams(components, params)}`, signature: `${label}=:${sig.toString("base64")}:` };
}

/** Verify raw signature bytes over a base with a public JWK (Ed25519, or P-256 for ecdsa-p256-sha256). */
export function verifyWithJwk(jwk: Jwk, base: string, signature: Uint8Array): boolean {
  try {
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string" && jwk.d === undefined) {
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
      return cryptoVerify(null, Buffer.from(base, "utf8"), key, Buffer.from(signature));
    }
    if (jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string" && jwk.d === undefined) {
      const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
      return cryptoVerify("sha256", Buffer.from(base, "utf8"), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature));
    }
  } catch {
    return false;
  }
  return false;
}

function jwkAlg(jwk: Jwk): string {
  return jwk.kty === "EC" ? "ecdsa-p256-sha256" : "ed25519";
}

export type RequestSignatureCheck =
  | { status: "absent" }
  | { status: "verified"; keyid: string; label: string }
  | { status: "invalid"; reason: string; keyid?: string };

export interface VerifyOptions {
  /** The body bytes exactly as received (the Content-Digest is recomputed over them). */
  body: Uint8Array;
  now: Date;
  /** A pinned `alp_use: http` key of the sending broker, or null. */
  keyFor: (keyid: string) => Promise<Jwk | null>;
  tag?: string;
  requiredComponents?: readonly string[];
  maxLifetimeSeconds?: number;
  clockSkewSeconds?: number;
  /** Returns false when the nonce was already used (replay of the same signed request). */
  useNonce?: (nonce: string, expires: number) => boolean;
}

/**
 * Check the profile's signature on a request. Signatures with other tags are ignored; with none of ours, the
 * result is `absent`. The first signature carrying our tag must pass every check.
 */
export async function verifyRequestSignature(req: SignableRequest, opts: VerifyOptions): Promise<RequestSignatureCheck> {
  const inputHeader = headerValue(req.headers, "signature-input");
  const sigHeader = headerValue(req.headers, "signature");
  if (inputHeader === undefined && sigHeader === undefined) return { status: "absent" };
  if (inputHeader === undefined || sigHeader === undefined) return { status: "invalid", reason: "Signature-Input and Signature must come together" };
  let inputs: Map<string, SfMember>;
  let sigs: Map<string, SfMember>;
  try {
    inputs = parseDictionary(inputHeader);
    sigs = parseDictionary(sigHeader);
  } catch {
    return { status: "invalid", reason: "malformed signature fields" };
  }
  const tag = opts.tag ?? FEDERATION_SIGNATURE_PROFILE.tag;
  let label: string | undefined;
  let input: SfInnerList | undefined;
  for (const [k, m] of inputs) {
    if (m.kind === "list" && m.params.get("tag") === tag) {
      label = k;
      input = m;
      break;
    }
  }
  if (!label || !input) return { status: "absent" };

  const components: string[] = [];
  for (const it of input.items) {
    if (typeof it.value !== "string" || it.params.size > 0) return { status: "invalid", reason: "unsupported component identifier" };
    components.push(it.value);
  }
  for (const required of opts.requiredComponents ?? FEDERATION_SIGNATURE_PROFILE.components) {
    if (!components.includes(required)) return { status: "invalid", reason: `the signature does not cover ${required}` };
  }
  const p = input.params;
  const created = p.get("created");
  const expires = p.get("expires");
  const nonce = p.get("nonce");
  const keyid = p.get("keyid");
  if (typeof created !== "number" || typeof expires !== "number" || typeof nonce !== "string" || typeof keyid !== "string") {
    return { status: "invalid", reason: "created, expires, nonce and keyid are required" };
  }
  const now = Math.floor(opts.now.getTime() / 1000);
  const skew = opts.clockSkewSeconds ?? FEDERATION_SIGNATURE_PROFILE.clockSkewSeconds;
  if (expires <= created || expires - created > (opts.maxLifetimeSeconds ?? FEDERATION_SIGNATURE_PROFILE.maxLifetimeSeconds)) {
    return { status: "invalid", reason: "expires must be after created and at most 300 seconds later", keyid };
  }
  if (created > now + skew) return { status: "invalid", reason: "created is in the future", keyid };
  if (now > expires + skew) return { status: "invalid", reason: "the request signature has expired", keyid };
  const sigMember = sigs.get(label);
  if (!sigMember || sigMember.kind !== "item" || !(sigMember.value instanceof Uint8Array)) return { status: "invalid", reason: "no signature for the label", keyid };
  if (components.includes("content-digest") && !checkContentDigest(headerValue(req.headers, "content-digest"), opts.body)) {
    return { status: "invalid", reason: "Content-Digest does not match the body", keyid };
  }
  const jwk = await opts.keyFor(keyid);
  if (!jwk) return { status: "invalid", reason: "unknown or unpinned key", keyid };
  const alg = p.get("alg");
  if (alg !== undefined && alg !== jwkAlg(jwk)) return { status: "invalid", reason: "alg does not match the key", keyid };
  let base: string;
  try {
    base = signatureBase(req, components, [...p.entries()]);
  } catch {
    return { status: "invalid", reason: "a covered component is missing", keyid };
  }
  if (!verifyWithJwk(jwk, base, sigMember.value)) return { status: "invalid", reason: "the signature did not verify", keyid };
  if (opts.useNonce && !opts.useNonce(nonce, expires)) return { status: "invalid", reason: "the nonce was already used", keyid };
  return { status: "verified", keyid, label };
}
