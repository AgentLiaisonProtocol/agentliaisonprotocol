// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkDomainDocument, homeBroker, keyCompromisedSince, parseTxtRecord, pinnedFederationKeys, wellKnownUrls } from "./domain.ts";
import { KeyRing } from "./keys.ts";
import type { DomainDocument } from "./types.ts";

const now = new Date("2026-11-09T14:00:00.000Z");

async function doc(): Promise<{ d: DomainDocument; ring: KeyRing }> {
  const ring = await KeyRing.generate(now);
  await ring.prepareNext(now);
  return {
    ring,
    d: {
      alp: "0.1",
      domain: "example.org",
      serial: 3,
      max_age: 3600,
      mode: "enforce",
      brokers: [
        { id: "https://broker.example.org", inbox: "https://broker.example.org/federation/inbox", jwks_uri: "https://broker.example.org/.well-known/jwks.json", jkt: ring.jkts(), principals: "*" },
        { id: "https://exec.example.org", inbox: "https://exec.example.org/federation/inbox", jwks_uri: "https://exec.example.org/.well-known/jwks.json", jkt: ring.jkts(), principals: ["alp:lee@example.org"] },
      ],
      security_contact: ["mailto:security@example.org"],
    },
  };
}

test("one home broker per address: the explicit list first, then the single * broker", async () => {
  const { d } = await doc();
  const checked = checkDomainDocument(d, "example.org");
  assert.equal(homeBroker(checked, "alp:lee@example.org")?.id, "https://exec.example.org");
  assert.equal(homeBroker(checked, "alp:ana@example.org")?.id, "https://broker.example.org");
  assert.equal(homeBroker(checked, "alp:ana@other.example"), undefined);
});

test("documents are refused for another domain, a lower serial, overlapping lists, two * brokers or foreign addresses", async () => {
  const { d } = await doc();
  assert.throws(() => checkDomainDocument(d, "other.example"), /expected other.example/);
  assert.throws(() => checkDomainDocument(d, "example.org", 4), /backwards/);
  const overlap = structuredClone(d);
  overlap.brokers.push({ ...overlap.brokers[1]!, id: "https://third.example.org" });
  assert.throws(() => checkDomainDocument(overlap, "example.org"), /overlapping/);
  const stars = structuredClone(d);
  stars.brokers[1]!.principals = "*";
  assert.throws(() => checkDomainDocument(stars, "example.org"));
  const foreign = structuredClone(d);
  foreign.brokers[1]!.principals = ["alp:lee@other.example"];
  assert.throws(() => checkDomainDocument(foreign, "example.org"), /own addresses/);
});

test("JWKS pinning: only pinned keys, kid = thumbprint, federation keys returned", async () => {
  const { d, ring } = await doc();
  const entry = d.brokers[0]!;
  const keys = await pinnedFederationKeys(ring.jwks(), entry);
  assert.equal(keys.keys.length, 2);
  const stranger = await KeyRing.generate(now);
  // A key the domain doesn't pin is ignored, never used (spec 4.8 rule 1); so is a revoked one.
  assert.deepEqual((await pinnedFederationKeys({ keys: [...ring.jwks().keys, ...stranger.jwks().keys] }, entry)).keys.map((k) => k.kid), ring.jwks().keys.map((k) => k.kid));
  assert.deepEqual((await pinnedFederationKeys(ring.jwks(), entry, [ring.kid])).keys.filter((k) => k.kid === ring.kid), []);
  await assert.rejects(pinnedFederationKeys({ keys: [{ ...ring.jwks().keys[0]!, d: "secret" }] }, entry));
});

test("revoked_jkt, well-known locations and the TXT record", async () => {
  const { d, ring } = await doc();
  d.revoked_jkt = [{ jkt: ring.kid, compromised_since: "2026-11-01T00:00:00Z" }];
  assert.equal(keyCompromisedSince(checkDomainDocument(d, "example.org"), ring.kid), "2026-11-01T00:00:00Z");
  assert.deepEqual(wellKnownUrls("example.org"), ["https://example.org/.well-known/alp.json", "https://alp.example.org/.well-known/alp.json"]);
  assert.deepEqual(parseTxtRecord("v=ALP1; id=42"), { id: "42", serial: 42 });
  assert.deepEqual(parseTxtRecord("v=ALP1; id=20261101T0900"), { id: "20261101T0900" });
  assert.equal(parseTxtRecord("v=ALP1; url=https://evil.example"), null);
});
