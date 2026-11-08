// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeyRing, JWS_ALG } from "./keys.ts";
import { JWS_TYP, jwsKid, signDetached, verifyDetached } from "./jws.ts";

const now = new Date("2026-11-09T14:00:00.000Z");

test("key ring: kid is the RFC 7638 thumbprint, JWKS carries no private material", async () => {
  const ring = await KeyRing.generate(now);
  const jwks = ring.jwks();
  assert.equal(jwks.keys.length, 1);
  const k = jwks.keys[0]!;
  assert.equal(k.kty, "OKP");
  assert.equal(k.crv, "Ed25519");
  assert.equal(k.alg, JWS_ALG);
  assert.equal(k.d, undefined);
  assert.equal(k.kid, ring.kid);
  assert.match(ring.kid, /^[A-Za-z0-9_-]{43}$/);
});

test("detached JWS signs the JCS form and verifies regardless of key order", async () => {
  const ring = await KeyRing.generate(now);
  const obj = { b: 2, a: { y: [1, 2], x: "é" } };
  const sig = await signDetached(obj, JWS_TYP.envelope, ring);
  const [h, p, s] = sig.split(".");
  assert.ok(h && s);
  assert.equal(p, "");
  assert.equal(jwsKid(sig), ring.kid);
  const reordered = { a: { x: "é", y: [1, 2] }, b: 2 };
  const ok = await verifyDetached(reordered, sig, JWS_TYP.envelope, ring.jwks());
  assert.deepEqual(ok, { ok: true, kid: ring.kid, alg: JWS_ALG });
});

test("detached JWS rejects tampering, wrong typ, unknown keys and malformed input", async () => {
  const ring = await KeyRing.generate(now);
  const other = await KeyRing.generate(now);
  const obj = { msg: "hello", n: 1 };
  const sig = await signDetached(obj, JWS_TYP.receipt, ring);
  assert.deepEqual(await verifyDetached({ ...obj, n: 2 }, sig, JWS_TYP.receipt, ring.jwks()), { ok: false, failure: "invalid" });
  assert.deepEqual(await verifyDetached(obj, sig, JWS_TYP.envelope, ring.jwks()), { ok: false, failure: "wrong_typ" });
  assert.deepEqual(await verifyDetached(obj, sig, JWS_TYP.receipt, other.jwks()), { ok: false, failure: "unknown_kid" });
  // the attacker's own key published under the victim's kid still fails the signature
  const spoofed = { keys: [{ ...other.jwks().keys[0]!, kid: ring.kid }] };
  assert.deepEqual(await verifyDetached(obj, sig, JWS_TYP.receipt, spoofed), { ok: false, failure: "invalid" });
  assert.deepEqual(await verifyDetached(obj, "abc", JWS_TYP.receipt, ring.jwks()), { ok: false, failure: "malformed" });
  const [h, , s] = sig.split(".");
  const attached = `${h}.${Buffer.from("{}").toString("base64url")}.${s}`;
  assert.deepEqual(await verifyDetached(obj, attached, JWS_TYP.receipt, ring.jwks()), { ok: false, failure: "malformed" });
  const noneHeader = Buffer.from(JSON.stringify({ alg: "none", kid: ring.kid, typ: JWS_TYP.receipt })).toString("base64url");
  assert.deepEqual(await verifyDetached(obj, `${noneHeader}..${s}`, JWS_TYP.receipt, ring.jwks()), { ok: false, failure: "bad_alg" });
});

test("rotation: the retiring key keeps verifying until retire_at, then leaves the JWKS", async () => {
  const ring = await KeyRing.generate(now);
  const oldKid = ring.kid;
  const sigOld = await signDetached({ a: 1 }, JWS_TYP.envelope, ring);
  await ring.rotate(now, 3600);
  assert.notEqual(ring.kid, oldKid);
  assert.equal(ring.jwks().keys.length, 2);
  assert.equal((await verifyDetached({ a: 1 }, sigOld, JWS_TYP.envelope, ring.jwks())).ok, true);
  const sigNew = await signDetached({ a: 1 }, JWS_TYP.envelope, ring);
  assert.equal(jwsKid(sigNew), ring.kid);
  ring.prune(new Date(now.getTime() + 3599_000));
  assert.equal(ring.jwks().keys.length, 2);
  ring.prune(new Date(now.getTime() + 3600_000));
  assert.deepEqual(ring.jwks().keys.map((k) => k.kid), [ring.kid]);
  assert.equal((await verifyDetached({ a: 1 }, sigOld, JWS_TYP.envelope, ring.jwks())).ok, false);
  assert.equal((await verifyDetached({ a: 1 }, sigOld, JWS_TYP.envelope, ring.historicJwks())).ok, true);
});

test("key ring round-trips through its stored form and refuses malformed input", async () => {
  const ring = await KeyRing.generate(now);
  await ring.rotate(now, 60);
  const restored = KeyRing.fromJSON(JSON.parse(JSON.stringify(ring.toJSON())));
  assert.equal(restored.kid, ring.kid);
  const sig = await signDetached({ x: 1 }, JWS_TYP.grant, restored);
  assert.equal((await verifyDetached({ x: 1 }, sig, JWS_TYP.grant, ring.jwks())).ok, true);
  assert.throws(() => KeyRing.fromJSON({ version: 1, keys: [] }));
  const broken = ring.toJSON();
  broken.keys[0]!.private_jwk.d = undefined;
  assert.throws(() => KeyRing.fromJSON(broken));
});
