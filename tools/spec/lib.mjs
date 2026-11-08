// Shared helpers for the ALP v0.1 spec generator and validator.
// JCS (RFC 8785), strict I-JSON parsing, detached JWS (RFC 7515 App. F), RFC 7638 thumbprints,
// deterministic TEST keys, ULIDs, pointer patterns and the delivery sanitizer.
import crypto from "node:crypto";

export const CP = "0.1";
export const BASE = "tag:agentliaisonprotocol.org,2026-11-08:spec/0.1/schemas/";

// ---------------------------------------------------------------- encoding
export const b64url = (buf) => Buffer.from(buf).toString("base64url");
export const fromB64url = (s) => Buffer.from(s, "base64url");

export function sha256(data) {
  return "sha256:" + crypto.createHash("sha256").update(data).digest("base64url");
}
export const hashJson = (v) => sha256(canonicalize(v));

// ---------------------------------------------------------------- JCS (RFC 8785)
export function canonicalize(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
    return JSON.stringify(v); // ECMAScript Number serialization is the JCS number form
  }
  if (typeof v === "string") {
    if (!v.isWellFormed()) throw new Error("JCS: lone surrogate");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort(); // UTF-16 code unit order
    return "{" + keys.map((k) => {
      if (!k.isWellFormed()) throw new Error("JCS: lone surrogate in member name");
      return JSON.stringify(k) + ":" + canonicalize(v[k]);
    }).join(",") + "}";
  }
  throw new Error("JCS: unsupported value");
}

// ---------------------------------------------------------------- strict I-JSON parse
// Rejects duplicate member names, lone surrogates, and anything JSON.parse would not accept.
export function parseStrict(text) {
  let i = 0;
  const fail = (m) => { throw new Error(`I-JSON: ${m} at ${i}`); };
  const ws = () => { while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++; };
  const str = () => {
    if (text[i] !== '"') fail("expected string");
    let j = i + 1;
    while (j < text.length && text[j] !== '"') { if (text[j] === "\\") j++; j++; }
    if (j >= text.length) fail("unterminated string");
    const s = JSON.parse(text.slice(i, j + 1));
    if (!s.isWellFormed()) fail("lone surrogate");
    i = j + 1;
    return s;
  };
  const val = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const o = {}; const seen = new Set(); ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws(); const k = str();
        if (seen.has(k)) fail(`duplicate member name ${JSON.stringify(k)}`);
        seen.add(k); ws();
        if (text[i++] !== ":") fail("expected ':'");
        const v = val();
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return o; }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(val()); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (m && m[0].length) { i += m[0].length; const n = Number(m[0]); if (!Number.isFinite(n)) fail("number out of range"); return n; }
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(lit, i)) { i += lit.length; return v; }
    }
    fail("unexpected token");
  };
  const out = val(); ws();
  if (i !== text.length) fail("trailing data");
  return out;
}

// ---------------------------------------------------------------- keys
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Deterministic TEST-ONLY Ed25519 key from a name. Never use outside tests. */
export function testEd25519(name) {
  const seed = crypto.createHash("sha256").update("TEST-ONLY-key-v0.1:" + name).digest();
  const key = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const jwk = key.export({ format: "jwk" });
  return { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d };
}

/** Deterministic TEST-ONLY P-256 key from a name. */
export function testP256(name) {
  const d = crypto.createHash("sha256").update("TEST-ONLY-p256-v0.1:" + name).digest();
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey(); // 04 || X || Y
  return { kty: "EC", crv: "P-256", x: b64url(pub.subarray(1, 33)), y: b64url(pub.subarray(33, 65)), d: b64url(d) };
}

export function publicJwk(jwk) {
  const { d, ...pub } = jwk;
  return pub;
}

/** RFC 7638 thumbprint (base64url SHA-256 of the required members in lexicographic order). */
export function jkt(jwk) {
  let members;
  if (jwk.kty === "OKP") members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  else if (jwk.kty === "EC") members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  else throw new Error("unsupported kty");
  return crypto.createHash("sha256").update(canonicalize(members)).digest("base64url");
}

function keyObject(jwk, priv) {
  const k = priv ? jwk : publicJwk(jwk);
  const base = jwk.kty === "OKP" ? { kty: "OKP", crv: k.crv, x: k.x } : { kty: "EC", crv: k.crv, x: k.x, y: k.y };
  if (priv) base.d = k.d;
  return priv ? crypto.createPrivateKey({ key: base, format: "jwk" }) : crypto.createPublicKey({ key: base, format: "jwk" });
}

export const algOf = (jwk) => (jwk.kty === "OKP" && jwk.crv === "Ed25519" ? "Ed25519" : jwk.kty === "EC" && jwk.crv === "P-256" ? "ES256" : null);

function rawSign(alg, data, privJwk) {
  const key = keyObject(privJwk, true);
  if (alg === "Ed25519") return crypto.sign(null, data, key);
  if (alg === "ES256") return crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
  throw new Error("alg");
}
function rawVerify(alg, data, pubJwk, sig) {
  const key = keyObject(pubJwk, false);
  if (alg === "Ed25519") return crypto.verify(null, data, key, sig);
  if (alg === "ES256") return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
  return false;
}

// ---------------------------------------------------------------- detached JWS over JCS
export function withoutSig(obj, member = "broker_sig") {
  const { [member]: _s, ...rest } = obj;
  return rest;
}

/** Returns { sig, header, protectedB64, payloadB64, signingInput, jcs }. */
export function signDetached(obj, typ, privJwk, kid, member = "broker_sig") {
  const alg = algOf(privJwk);
  const header = { alg, kid, typ };
  const protectedB64 = b64url(Buffer.from(canonicalize(header), "utf8"));
  const jcs = canonicalize(withoutSig(obj, member));
  const payloadB64 = b64url(Buffer.from(jcs, "utf8"));
  const signingInput = protectedB64 + "." + payloadB64;
  const signature = rawSign(alg, Buffer.from(signingInput, "ascii"), privJwk);
  return { sig: protectedB64 + ".." + b64url(signature), header, protectedB64, payloadB64, signingInput, jcs };
}

export function parseHeader(sig) {
  if (typeof sig !== "string") return null;
  const parts = sig.split(".");
  if (parts.length !== 3 || parts[1] !== "") return null;
  try {
    const h = parseStrict(fromB64url(parts[0]).toString("utf8"));
    return h && typeof h === "object" && !Array.isArray(h) ? h : null;
  } catch { return null; }
}

/**
 * Verify a detached JWS. `keys` is a list of public JWKs that are acceptable (already filtered to pinned,
 * unrevoked keys of the right alp_use). The algorithm comes from the key, never from the header.
 */
export function verifyDetached(obj, expectedTyp, keys, member = "broker_sig") {
  const sig = obj[member];
  const parts = typeof sig === "string" ? sig.split(".") : [];
  if (parts.length !== 3 || parts[1] !== "") return { ok: false, failure: "malformed" };
  const header = parseHeader(sig);
  if (!header) return { ok: false, failure: "malformed" };
  const names = Object.keys(header).sort().join(",");
  if (names !== "alg,kid,typ") return { ok: false, failure: "header_members" }; // exactly alg, kid, typ (spec 8.7)
  if (header.typ !== expectedTyp) return { ok: false, failure: "wrong_typ" };
  if (typeof header.kid !== "string") return { ok: false, failure: "unknown_kid" };
  const key = keys.find((k) => k.kid === header.kid);
  if (!key) return { ok: false, failure: "unknown_kid" };
  const alg = algOf(key);
  if (!alg || header.alg !== alg || (key.alg && key.alg !== alg)) return { ok: false, failure: "bad_alg" };
  const payloadB64 = b64url(Buffer.from(canonicalize(withoutSig(obj, member)), "utf8"));
  const ok = rawVerify(alg, Buffer.from(parts[0] + "." + payloadB64, "ascii"), key, fromB64url(parts[2]));
  return ok ? { ok: true, kid: header.kid, alg } : { ok: false, failure: "invalid" };
}

// ---------------------------------------------------------------- ULID
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function ulid(ms, seed) {
  let t = BigInt(ms);
  let time = "";
  for (let k = 0; k < 10; k++) { time = CROCKFORD[Number(t % 32n)] + time; t /= 32n; }
  const h = crypto.createHash("sha256").update("ulid:" + seed).digest();
  let r = BigInt("0x" + h.subarray(0, 10).toString("hex"));
  let rand = "";
  for (let k = 0; k < 16; k++) { rand = CROCKFORD[Number(r % 32n)] + rand; r /= 32n; }
  return time + rand;
}

// ---------------------------------------------------------------- time
export const iso = (ms) => new Date(ms).toISOString().replace(/\.000Z$/, "Z");
export const ms = (s) => Date.parse(s);

// ---------------------------------------------------------------- pointers (envelope-relative)
export function parsePointer(p) {
  if (p === "") return [];
  if (!p.startsWith("/")) throw new Error("bad pointer " + p);
  return p.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}
export const formatPointer = (tokens) => tokens.map((t) => "/" + String(t).replace(/~/g, "~0").replace(/\//g, "~1")).join("");

/** Leaves of the body (as /body/...) plus /note when present. Empty containers below body count as leaves. */
export function leaves(env) {
  const out = [];
  const walk = (v, path) => {
    if (Array.isArray(v)) {
      if (v.length === 0 && path.length > 1) out.push(formatPointer(path));
      v.forEach((x, i) => walk(x, [...path, String(i)]));
    } else if (v && typeof v === "object") {
      const keys = Object.keys(v);
      if (keys.length === 0 && path.length > 1) out.push(formatPointer(path));
      for (const k of keys) walk(v[k], [...path, k]);
    } else out.push(formatPointer(path));
  };
  walk(env.body ?? {}, ["body"]);
  if (typeof env.note === "string") out.push("/note");
  return out;
}

/** Prefix match: pattern covers pointer when every pattern token equals the pointer token or is "*". */
export function prefixMatch(pattern, pointer) {
  const p = parsePointer(pattern), t = parsePointer(pointer);
  if (p.length > t.length) return false;
  return p.every((tok, i) => tok === "*" || tok === t[i]);
}
export function exactMatch(pattern, pointer) {
  const p = parsePointer(pattern), t = parsePointer(pointer);
  return p.length === t.length && p.every((tok, i) => tok === "*" || tok === t[i]);
}

/** Walk a type's body schema along an envelope-relative pointer; true when the leaf is free text. */
export function isTextLocation(pointer, bodySchema) {
  if (pointer === "/note") return true;
  const t = parsePointer(pointer);
  if (t[0] !== "body") return false;
  let s = bodySchema;
  for (const tok of t.slice(1)) {
    if (!s) return false;
    if (s.type === "array" || s.items) s = s.items;
    else if (s.properties) s = s.properties[tok];
    else return false;
  }
  return !!s && s["x-alp-text"] === "untrusted";
}

/** A free-text location is covered only by an exact pattern; any other leaf by a prefix pattern. */
export function covered(pointer, patterns, text) {
  return patterns.some((p) => (text ? exactMatch(p, pointer) : prefixMatch(p, pointer)));
}

export function getAt(obj, pointer) {
  let v = obj;
  for (const t of parsePointer(pointer)) { if (v == null) return undefined; v = v[t]; }
  return v;
}

/** Remove the given leaves (envelope-relative) and prune containers they emptied. */
export function removeLeaves(env, pointers) {
  const copy = structuredClone(env);
  const sorted = [...pointers].sort((a, b) => b.length - a.length);
  for (const p of sorted) {
    if (p === "/note") { delete copy.note; continue; }
    const t = parsePointer(p);
    const chain = [copy];
    let v = copy;
    for (const tok of t.slice(0, -1)) { v = v?.[tok]; chain.push(v); }
    const parent = chain[chain.length - 1];
    if (parent == null) continue;
    const last = t[t.length - 1];
    if (Array.isArray(parent)) parent.splice(Number(last), 1); else delete parent[last];
    // prune emptied containers up to (not including) body
    for (let k = chain.length - 1; k >= 2; k--) {
      const c = chain[k];
      const empty = Array.isArray(c) ? c.length === 0 : c && Object.keys(c).length === 0;
      if (!empty) break;
      const pc = chain[k - 1], key = t[k - 1];
      if (Array.isArray(pc)) pc.splice(Number(key), 1); else delete pc[key];
    }
  }
  return copy;
}

// ---------------------------------------------------------------- delivery sanitizer (spec 12.1.6)
const INVISIBLE = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;
const TAG = /<\/?[A-Za-z][A-Za-z0-9:-]*(?:\s[^<>]*)?\/?>/g;
const URL_RE = /\b(https?|ftp):\/\/([^\s\/?#<>"'`]+)/gi;
export function sanitizeText(s) {
  let out = s.replace(INVISIBLE, "");
  out = out.replace(TAG, "");
  out = out.replace(URL_RE, (_m, scheme, host) => {
    const sc = scheme.toLowerCase() === "https" ? "hxxps" : scheme.toLowerCase() === "http" ? "hxxp" : "fxp";
    return sc + "://" + host.replace(/\./g, "[.]");
  });
  return out;
}

// ---------------------------------------------------------------- baseline DLP (spec 6.9)
function luhn(digits) {
  let sum = 0, alt = false;
  for (let k = digits.length - 1; k >= 0; k--) {
    let n = digits.charCodeAt(k) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}
export function baselineDlp(text) {
  const hits = new Set();
  for (const m of text.matchAll(/(?:\d[ -]?){12,18}\d/g)) {
    const d = m[0].replace(/[ -]/g, "");
    if (d.length >= 13 && d.length <= 19 && luhn(d)) hits.add("payment_card");
  }
  if (/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(text)) hits.add("private_key");
  if (/\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/.test(text)) hits.add("credential");
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) hits.add("government_id");
  return [...hits].sort();
}
