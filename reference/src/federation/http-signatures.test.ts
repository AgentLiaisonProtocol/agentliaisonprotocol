// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { KeyRing } from "../core/keys.ts";
import { PROTOCOL } from "../core/protocol.ts";
import type { Jwk } from "../core/types.ts";
import {
  FEDERATION_SIGNATURE_PROFILE,
  StructuredFieldError,
  checkContentDigest,
  componentValue,
  contentDigest,
  parseDictionary,
  signRequest,
  signatureBase,
  verifyRequestSignature,
  verifyWithJwk,
} from "./http-signatures.ts";
import type { SignableRequest } from "./http-signatures.ts";

// RFC 9421 Appendix B.1.4 (test-key-ed25519) and B.2 (the test request), copied from the RFC.
const RFC_KEY = { kty: "OKP", crv: "Ed25519", kid: "test-key-ed25519", d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU", x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" };
const RFC_REQUEST: SignableRequest = {
  method: "POST",
  targetUri: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    Host: "example.com",
    Date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "Content-Type": "application/json",
    "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    "Content-Length": "18",
  },
};
const RFC_BODY = Buffer.from('{"hello": "world"}');

test("RFC 9421 B.2.6: the Ed25519 signature base and signature match the RFC exactly", () => {
  const components = ["date", "@method", "@path", "@authority", "content-type", "content-length"];
  const base = signatureBase(RFC_REQUEST, components, [["created", 1618884473], ["keyid", "test-key-ed25519"]]);
  assert.equal(
    base,
    [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@method": POST',
      '"@path": /foo',
      '"@authority": example.com',
      '"content-type": application/json',
      '"content-length": 18',
      '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    ].join("\n"),
  );
  const key = createPrivateKey({ key: RFC_KEY, format: "jwk" });
  const sig = cryptoSign(null, Buffer.from(base), key).toString("base64");
  assert.equal(sig, "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==");
  assert.equal(verifyWithJwk({ kty: "OKP", crv: "Ed25519", x: RFC_KEY.x }, base, Buffer.from(sig, "base64")), true);
  // The RFC's Signature-Input and Signature fields parse to the same thing.
  const input = parseDictionary('sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"');
  const m = input.get("sig-b26");
  assert.equal(m?.kind, "list");
  const signature = parseDictionary(`sig-b26=:${sig}:`).get("sig-b26");
  assert.ok(signature?.kind === "item" && signature.value instanceof Uint8Array && Buffer.from(signature.value).toString("base64") === sig);
});

test("RFC 9421 2.2: derived components from the RFC's examples", () => {
  const req: SignableRequest = { method: "POST", targetUri: "https://www.example.com/path?param=value", headers: {} };
  assert.equal(componentValue("@target-uri", req), "https://www.example.com/path?param=value");
  assert.equal(componentValue("@authority", req), "www.example.com");
  assert.equal(componentValue("@scheme", req), "https");
  assert.equal(componentValue("@request-target", req), "/path?param=value");
  assert.equal(componentValue("@path", req), "/path");
  assert.equal(componentValue("@query", req), "?param=value");
  assert.equal(componentValue("@query", { ...req, targetUri: "https://www.example.com/path" }), "?");
  assert.equal(componentValue("x-two", { ...req, headers: { "X-Two": [" a ", "b "] } }), "a, b");
  assert.throws(() => componentValue("@status", req), StructuredFieldError);
  assert.throws(() => componentValue("missing", req), StructuredFieldError);
});

test("RFC 9530: Content-Digest values match the RFC examples (sha-256 and sha-512)", () => {
  assert.equal(contentDigest(Buffer.from('{"hello": "world"}\n'), "sha-256"), "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:");
  assert.equal(contentDigest(RFC_BODY, "sha-512"), "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:");
  assert.equal(checkContentDigest(RFC_REQUEST.headers["Content-Digest"] as string, RFC_BODY), true);
  assert.equal(checkContentDigest(`${contentDigest(RFC_BODY)}, ${contentDigest(RFC_BODY, "sha-512")}`, RFC_BODY), true);
  assert.equal(checkContentDigest(contentDigest(RFC_BODY), Buffer.from('{"hello": "world!"}')), false);
  assert.equal(checkContentDigest("md5=:AAAA:", RFC_BODY), false, "no supported algorithm");
  assert.equal(checkContentDigest(undefined, RFC_BODY), false);
});

const INBOX = "https://broker-b.example/federation/inbox";
const NOW = new Date("2026-11-09T14:00:00Z");
const CREATED = Math.floor(NOW.getTime() / 1000);

async function signed(body: Buffer, opts: { created?: number; expires?: number; components?: string[]; tag?: string; nonce?: string } = {}) {
  const ring = await KeyRing.generate(NOW, "http");
  const headers: Record<string, string> = { "content-type": "application/json", "content-digest": contentDigest(body) };
  const created = opts.created ?? CREATED;
  Object.assign(
    headers,
    signRequest({ method: "POST", targetUri: INBOX, headers }, { kid: ring.kid, privateKey: ring.privateKey(ring.kid) }, {
      created,
      expires: opts.expires ?? created + 300,
      nonce: opts.nonce ?? "n-1",
      ...(opts.tag ? { tag: opts.tag } : {}),
      ...(opts.components ? { components: opts.components } : {}),
    }),
  );
  const jwk = ring.jwks().keys[0] as Jwk;
  return { ring, headers, jwk };
}

function verify(headers: Record<string, string>, body: Buffer, jwk: Jwk | null, extra: { target?: string; now?: Date; useNonce?: (n: string, e: number) => boolean } = {}) {
  return verifyRequestSignature({ method: "POST", targetUri: extra.target ?? INBOX, headers }, { body, now: extra.now ?? NOW, keyFor: async () => jwk, ...(extra.useNonce ? { useNonce: extra.useNonce } : {}) });
}

test("the federation profile (spec 12.2.2): covers @method, @target-uri, content-type and content-digest with created, expires, nonce, keyid and the tag", async () => {
  const body = Buffer.from('{"alp":"0.1"}');
  const { headers, jwk, ring } = await signed(body);
  assert.match(headers["signature-input"] as string, new RegExp(`^${PROTOCOL.id}=\\("@method" "@target-uri" "content-type" "content-digest"\\);created=\\d+;expires=\\d+;nonce="n-1";keyid="[A-Za-z0-9_-]{43}";tag="${PROTOCOL.typPrefix}fed"$`));
  assert.equal(FEDERATION_SIGNATURE_PROFILE.tag, `${PROTOCOL.typPrefix}fed`);
  const ok = await verify(headers, body, jwk);
  assert.deepEqual(ok, { status: "verified", keyid: ring.kid, label: PROTOCOL.id });
});

test("request signature failures: changed body, rewritten target URI, expiry, a future created, a long lifetime, a missing component, an unknown key, a reused nonce", async () => {
  const body = Buffer.from('{"alp":"0.1"}');
  const { headers, jwk } = await signed(body);
  const reason = async (p: Promise<unknown>): Promise<string> => {
    const r = (await p) as { status: string; reason?: string };
    assert.equal(r.status, "invalid");
    return r.reason ?? "";
  };
  assert.match(await reason(verify(headers, Buffer.from('{"alp":"0.2"}'), jwk)), /Content-Digest/);
  assert.match(await reason(verify(headers, body, jwk, { target: "https://proxy.internal.example/federation/inbox" })), /did not verify/);
  assert.match(await reason(verify(headers, body, jwk, { now: new Date(NOW.getTime() + 400_000) })), /expired/);
  assert.match(await reason(verify(headers, body, jwk, { now: new Date(NOW.getTime() - 120_000) })), /future/);
  const long = await signed(body, { expires: CREATED + 301 });
  assert.match(await reason(verify(long.headers, body, long.jwk)), /300 seconds/);
  const partial = await signed(body, { components: ["@method", "@target-uri", "content-type"] });
  assert.match(await reason(verify(partial.headers, body, partial.jwk)), /content-digest/);
  assert.match(await reason(verify(headers, body, null)), /unknown or unpinned key/);
  const used = new Set<string>();
  const useNonce = (n: string): boolean => (used.has(n) ? false : (used.add(n), true));
  assert.equal((await verify(headers, body, jwk, { useNonce })).status, "verified");
  assert.match(await reason(verify(headers, body, jwk, { useNonce })), /nonce/);
  assert.match(await reason(verify({ ...headers, signature: "alp=:AAAA:" }, body, jwk)), /did not verify/);
  assert.match(await reason(verify({ "signature-input": headers["signature-input"] as string }, body, jwk)), /together/);
});

test("signatures with another tag are ignored (absent), as are requests with no signature", async () => {
  const body = Buffer.from("{}");
  const other = await signed(body, { tag: "web-bot-auth" });
  assert.deepEqual(await verify(other.headers, body, other.jwk), { status: "absent" });
  assert.deepEqual(await verify({ "content-type": "application/json" }, body, null), { status: "absent" });
});

test("verification also accepts an ES256 key (ecdsa-p256-sha256, raw r||s)", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as Jwk;
  const base = '"@method": POST';
  const sig = cryptoSign("sha256", Buffer.from(base), { key: privateKey, dsaEncoding: "ieee-p1363" });
  assert.equal(verifyWithJwk(jwk, base, sig), true);
  assert.equal(verifyWithJwk(jwk, `${base} `, sig), false);
  assert.equal(verifyWithJwk({ ...jwk, d: "x" }, base, sig), false, "a private JWK is never used to verify");
});

test("structured fields: dictionaries parse, malformed ones are refused", () => {
  const d = parseDictionary('a=("x" "y");created=1;keyid="k", b=?1, c=:AQID:, d=tok;p');
  const a = d.get("a");
  assert.ok(a?.kind === "list");
  assert.deepEqual(a.items.map((i) => i.value), ["x", "y"]);
  assert.equal(a.params.get("created"), 1);
  assert.equal(d.get("b")?.kind === "item" && d.get("b")?.kind === "item" ? (d.get("b") as { value: unknown }).value : undefined, true);
  assert.deepEqual([...((d.get("c") as { value: Uint8Array }).value)], [1, 2, 3]);
  for (const bad of ["a=(", 'a="unterminated', "a=1,", "A=1", "a=1.5", "a=:not base64!:"]) {
    assert.throws(() => parseDictionary(bad), StructuredFieldError, bad);
  }
});
