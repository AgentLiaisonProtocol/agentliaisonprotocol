// SPDX-License-Identifier: FSL-1.1-ALv2
// The HTTPS resolver: discovery locations, max_age caching, rollback, failure caching, rate limits, remembered
// revocations, the TXT hint and JWKS caching. Two scripted servers on ports 47151 (location 1, the broker's JWKS and
// other test domains) and 47152 (location 2), reached through the dev host map. A ManualClock moves time.

import { test, after, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { ManualClock } from "../core/clock.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { KeyRing } from "../core/keys.ts";
import type { DomainDocument } from "../core/types.ts";
import { brokerEntry, buildDomainDocument } from "./domain-authority.ts";
import { HardenedFetcher } from "./fetcher.ts";
import { DiscoveryError, HttpsDomainResolver, StaticTxtLookup } from "./resolver.ts";
import type { ResolverOptions } from "./resolver.ts";
import { ScriptedServer } from "./testing.ts";
import { FEDERATION_TEST_PORT_BASE } from "../test-ports.ts";

const P1 = FEDERATION_TEST_PORT_BASE + 1;
const P2 = FEDERATION_TEST_PORT_BASE + 2;
const WELL_KNOWN = `/.well-known/${PROTOCOL.wellKnownFile}`;
const ALT = (domain: string): string => `https://${PROTOCOL.hostLabel}.${domain}`;
const TXT = `${PROTOCOL.txtLabel}.example.test`;
const V = PROTOCOL.txtVersion;
const JWKS = "/.well-known/jwks.json";
const BROKER = "https://broker.example.test";
const loc1 = new ScriptedServer();
const loc2 = new ScriptedServer();
const fetcher = new HardenedFetcher({
  devHosts: {
    "https://example.test": `http://127.0.0.1:${P1}`,
    [ALT("example.test")]: `http://127.0.0.1:${P2}`,
    [BROKER]: `http://127.0.0.1:${P1}`,
    "https://second.test": `http://127.0.0.1:${P1}`,
    [ALT("second.test")]: `http://127.0.0.1:${P2}`,
    "https://third.test": `http://127.0.0.1:${P1}`,
  },
  timeoutMs: 1000,
});
let ring: KeyRing;

before(async () => {
  ring = await KeyRing.generate(new Date("2026-11-09T14:00:00Z"));
  await loc1.listen(P1);
  await loc2.listen(P2);
});
after(async () => {
  await loc1.close();
  await loc2.close();
});
beforeEach(() => {
  loc1.routes.clear();
  loc2.routes.clear();
  loc1.hits.length = 0;
  loc2.hits.length = 0;
});

function doc(serial: number, extra: Partial<DomainDocument> = {}, domain = "example.test"): DomainDocument {
  return { ...buildDomainDocument({ domain, serial, maxAge: 600, brokers: [brokerEntry({ id: BROKER, keys: [ring], principals: "*" })] }), ...extra };
}

function resolver(extra: Partial<ResolverOptions> = {}): { r: HttpsDomainResolver; clock: ManualClock } {
  const clock = new ManualClock();
  return { r: new HttpsDomainResolver({ fetcher, clock, ...extra }), clock };
}

async function discoveryError(p: Promise<unknown>): Promise<DiscoveryError> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof DiscoveryError, String(err));
    assert.equal(err.code, "discovery_failed");
    assert.doesNotMatch(err.message, /HTTP|ECONN|timed out|127\.0\.0\.1/, "fetch details never leave the resolver");
    return err;
  }
  assert.fail("expected discovery to fail");
}

test("location 1 is fetched once and cached for max_age; after max_age it is fetched again", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const { r, clock } = resolver();
  assert.equal((await r.domainDocument("example.test")).serial, 1);
  assert.equal((await r.domainDocument("example.test")).serial, 1);
  assert.equal(loc1.count(WELL_KNOWN), 1);
  clock.advance(599);
  await r.domainDocument("example.test");
  assert.equal(loc1.count(WELL_KNOWN), 1);
  clock.advance(2);
  await r.domainDocument("example.test");
  assert.equal(loc1.count(WELL_KNOWN), 2);
});

test("grants expire: a document is never used past max_age, even when the refresh fails; failures are cached", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const { r, clock } = resolver();
  await r.domainDocument("example.test");
  loc1.routes.set(WELL_KNOWN, { status: 503 });
  assert.equal((await r.domainDocument("example.test", { refresh: true })).serial, 1, "inside max_age the cached copy stays usable");
  clock.advance(601);
  const e = await discoveryError(r.domainDocument("example.test"));
  assert.equal(e.absent, false);
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const hits = loc1.count(WELL_KNOWN);
  await discoveryError(r.domainDocument("example.test"));
  assert.equal(loc1.count(WELL_KNOWN), hits, "the failure is cached for 60 seconds: no request");
  clock.advance(61);
  assert.equal((await r.domainDocument("example.test")).serial, 1);
});

test("location 2 is tried only after a 404 or 410 at location 1; any other failure is temporary and has no fallback", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 404 });
  loc2.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const first = resolver();
  assert.equal((await first.r.domainDocument("example.test")).serial, 1);
  assert.ok(first.r.diagnostics.some((d) => d.event === "fallback_location"));

  loc1.routes.set(WELL_KNOWN, { status: 500 });
  const second = resolver();
  const before = loc2.count(WELL_KNOWN);
  await discoveryError(second.r.domainDocument("example.test"));
  assert.equal(loc2.count(WELL_KNOWN), before, "no fallback after a 500");

  loc1.routes.set(WELL_KNOWN, { status: 301, headers: { location: `${ALT("example.test")}${WELL_KNOWN}` } });
  await discoveryError(resolver().r.domainDocument("example.test"));
  assert.equal(loc2.count(WELL_KNOWN), before, "a redirect is neither followed nor a reason to fall back");

  loc1.routes.set(WELL_KNOWN, { status: 404 });
  loc2.routes.set(WELL_KNOWN, { status: 410 });
  const none = await discoveryError(resolver().r.domainDocument("example.test"));
  assert.equal(none.absent, true, "the domain publishes no document");
});

test("rollback: a lower serial is refused, and so is the same serial with different content", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(2) });
  const { r, clock } = resolver();
  await r.domainDocument("example.test");
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  clock.advance(601);
  await discoveryError(r.domainDocument("example.test"));
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(2, { max_age: 900 }) });
  clock.advance(61);
  await discoveryError(r.domainDocument("example.test"));
  assert.ok(r.diagnostics.some((d) => d.event === "invalid" && /same serial/.test(d.detail ?? "")));
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(3) });
  clock.advance(61);
  assert.equal((await r.domainDocument("example.test")).serial, 3);
});

test("a document is refused when a broker's endpoints are not on its own origin, or when it is for another domain", async () => {
  const bad = doc(1);
  (bad.brokers[0] as { inbox: string }).inbox = "https://elsewhere.example/federation/inbox";
  loc1.routes.set(WELL_KNOWN, { status: 200, body: bad });
  await discoveryError(resolver().r.domainDocument("example.test"));
  loc1.routes.set(WELL_KNOWN, { status: 200, body: { ...doc(1), domain: "other.test" } });
  await discoveryError(resolver().r.domainDocument("example.test"));
});

test("discovery of never-seen domains is rate-limited", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const { r } = resolver({ newDomainsPerMinute: 1 });
  await r.domainDocument("example.test");
  const hits = loc1.hits.length;
  await discoveryError(r.domainDocument("third.test"));
  assert.equal(loc1.hits.length, hits, "refused without a request");
  assert.ok(r.diagnostics.some((d) => d.event === "new_domain_rate_limited"));
});

test("the discovery budget is per requester: junk from one source doesn't block first contact from another", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  const { r } = resolver({ newDomainsPerMinute: 1 });
  await discoveryError(r.domainDocument("junk-one.test", { budget: "203.0.113.9" }));
  await discoveryError(r.domainDocument("junk-two.test", { budget: "203.0.113.9" }));
  assert.ok(r.diagnostics.some((d) => d.event === "new_domain_rate_limited"), "the second never-seen domain from one source waits");
  assert.equal((await r.domainDocument("example.test", { budget: "198.51.100.7" })).serial, 1, "another source still gets its first contact");
});

test("restrictions persist: a revoked key stays revoked for 7 days after the last document that listed it", async () => {
  const compromised = { jkt: "A".repeat(43), compromised_since: "2026-11-09T13:00:00.000Z" };
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1, { revoked_jkt: [compromised] }) });
  const { r, clock } = resolver();
  assert.deepEqual((await r.domainDocument("example.test")).revoked_jkt, [compromised]);
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(2) });
  clock.advance(601);
  const later = await r.domainDocument("example.test");
  assert.equal(later.serial, 2);
  assert.deepEqual(later.revoked_jkt, [compromised], "a newer document dropped it; the broker keeps applying it");
  clock.advance(7 * 24 * 3600);
  assert.equal((await r.domainDocument("example.test")).revoked_jkt, undefined, "gone after 7 days");
});

test("the TXT record is only a hint: a higher id refreshes early; a record with any other member, or two records, is ignored", async () => {
  const txt = new StaticTxtLookup();
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  // Checks every 60 seconds here, so every step stays inside the document's max_age (600).
  const { r, clock } = resolver({ txt, txtCheckSeconds: 60 });
  await r.domainDocument("example.test");
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(2) });
  txt.set(TXT, [`v=${V}; id=2`]);
  clock.advance(30);
  assert.equal((await r.domainDocument("example.test")).serial, 1, "checked at most once per interval");
  clock.advance(31);
  assert.equal((await r.domainDocument("example.test")).serial, 2);

  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(3) });
  txt.set(TXT, [`v=${V}; id=3; url=https://elsewhere.example/doc.json`]);
  clock.advance(61);
  assert.equal((await r.domainDocument("example.test")).serial, 2, "a record that points anywhere is ignored");
  txt.set(TXT, [`v=${V}; id=3`, `v=${V}; id=4`]);
  clock.advance(61);
  assert.equal((await r.domainDocument("example.test")).serial, 2, "more than one record is ignored");
  assert.equal(loc1.hits.some((h) => h.path.includes("elsewhere")), false);
});

test("JWKS: cached, bounded by the max_age of the document that lists it, and a forced refresh at most once a minute", async () => {
  loc1.routes.set(WELL_KNOWN, { status: 200, body: doc(1) });
  loc1.routes.set(JWKS, { status: 200, headers: { "content-type": "application/jwk-set+json" }, body: ring.jwks() });
  const { r, clock } = resolver();
  await r.domainDocument("example.test");
  const uri = `${BROKER}${JWKS}`;
  await r.jwks(uri);
  await r.jwks(uri);
  assert.equal(loc1.count(JWKS), 1);
  await r.jwks(uri, { refresh: true });
  await r.jwks(uri, { refresh: true });
  assert.equal(loc1.count(JWKS), 2, "the second forced refresh within a minute is skipped");
  clock.advance(61);
  await r.jwks(uri, { refresh: true });
  assert.equal(loc1.count(JWKS), 3);
  clock.advance(600);
  await r.jwks(uri);
  assert.equal(loc1.count(JWKS), 4, "never cached past the document's max_age (600)");
  loc1.routes.set(JWKS, { status: 200, body: { not: "a jwks" } });
  clock.advance(601);
  await discoveryError(r.jwks(uri));
});
