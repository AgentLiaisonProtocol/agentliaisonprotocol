// Every check passes on the correct fake, and fails (or warns, for a recommended check) under at least one fault. Each fault
// makes exactly the checks listed for it fail or warn: a prerequisite failure makes dependent checks skip, never fail.
import "./guard.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS } from "../catalog.mjs";
import { runChecks, parseArgs, exitCode } from "../check.mjs";
import { createFakeBroker, FAULTS, VARIANTS } from "./fake-broker.mjs";
import { toText, toJson } from "../report.mjs";

const PROBES = ["inbox.version", "inbox.strict-json", "inbox.schema", "inbox.lifetime", "inbox.created-ahead", "inbox.delegate-owner", "inbox.unknown-sender-domain"];

/**
 * For each fault, the checks that must fail (required) or warn (recommended); every other check must pass or skip, except
 * those listed in UNDECIDED, which must be reported as "could not decide".
 */
export const EXPECT = {
  "document-missing": ["document.found"],
  // A peer stops at a location 1 that redirects or refuses, so the document at location 2 is never found.
  "location-1-redirects": ["document.found", "document.fallback"],
  "location-1-forbidden": ["document.found", "document.fallback"],
  // A certificate that does not validate at location 1 stops every peer there (Section 4.3), and every peer sees it.
  "location-1-tls": ["document.found", "document.fallback", "document.tls"],
  "location-1-tls-location-2-serves": ["document.found", "document.fallback", "document.tls"],
  // Decided whatever location 2 answered: a peer never reads it.
  "location-1-tls-location-2-busy": ["document.found", "document.fallback", "document.tls"],
  // After a 404 at location 1 a peer uses location 2, so a certificate that does not validate there is decided too.
  "location-2-tls": ["document.found", "document.tls"],
  "document-text-type": ["document.content-type"],
  "document-oversize": ["document.size"],
  // Over 256 KiB, alp-check reads no further: only the size check speaks, and the rest skip with that reason.
  "document-huge": ["document.size"],
  "document-extra-member": ["document.schema"],
  // The listed alp:guest@example.org is then not on the document's `domain` either, which 4.2.1 also forbids.
  "document-wrong-domain": ["document.domain-matches", "document.addresses-on-domain"],
  "document-duplicate-ids": ["document.unique-ids"],
  "document-two-wildcards": ["document.one-wildcard", "document.schema"],
  "document-overlap": ["document.no-overlap"],
  "document-foreign-address": ["document.addresses-on-domain"],
  "document-url-off-origin": ["document.urls-on-origin"],
  "document-revoked-pinned": ["document.revoked-not-pinned"],
  "jwks-missing": ["keys.served"],
  "jwks-text-type": ["keys.content-type"],
  "jwks-oversize": ["keys.size"],
  "jwks-huge": ["keys.size"],
  "jwks-private-member": ["keys.schema"],
  "jwks-unpinned-federation": ["keys.no-unpinned-federation"],
  "jkt-unpublished": ["keys.current-key-pinned", "keys.no-unpinned-federation"],
  "kid-not-thumbprint": ["keys.kid-thumbprint"],
  "txt-extra-member": ["dns.txt-grammar"],
  "txt-two-records": ["dns.txt-grammar"],
  "txt-old-id": ["dns.txt-id-serial"],
  "prm-wrong-resource": ["signin.prm"],
  "prm-no-authorization-servers": ["signin.prm-authorization-server"],
  "prm-missing-send": ["signin.prm-scopes"],
  "as-metadata-missing": ["signin.as-metadata"],
  "as-wrong-issuer": ["signin.as-metadata", "signin.oidc-discovery"],
  "oidc-missing": ["signin.oidc-discovery"],
  "pkce-plain": ["signin.pkce-s256"],
  "no-iss-parameter": ["signin.iss-parameter"],
  "no-cimd": ["signin.cimd"],
  "no-revocation-endpoint": ["signin.revocation"],
  "mcp-challenge-no-resource-metadata": ["binding.mcp-challenge"],
  "rest-open": ["binding.rest-challenge"],
  "inbox-version-after-schema": ["inbox.version"],
  "inbox-lenient-json": ["inbox.strict-json"],
  "inbox-no-schema": ["inbox.schema"],
  "inbox-no-lifetime-limit": ["inbox.lifetime"],
  "inbox-no-clock-check": ["inbox.created-ahead"],
  "inbox-no-delegate-check": ["inbox.delegate-owner"],
  "inbox-no-to-delegate-check": ["inbox.delegate-owner"],
  "inbox-no-expiry-order": ["inbox.lifetime"],
  "inbox-accepts-unknown-domains": ["inbox.unknown-sender-domain"],
  // An error body with no `error` object hides the code from every probe, so each probe fails with the shape check.
  "inbox-flat-errors": [...PROBES.filter((p) => p !== "inbox.unknown-sender-domain"), "inbox.error-shape"],
  "inbox-wrong-status": ["inbox.error-shape"],
  "inbox-error-with-receipt": ["inbox.error-shape"],
  "inbox-no-retry-after": ["inbox.retry-after"],
};

const D = "example.org";
const B = "https://broker.example.org";
const H = "https://hosted.example.net";
/** For each fault, one of its results: the check, the subject, and a fragment of the message, so a check that fails for the wrong reason is caught. */
export const DETAIL = {
  "document-missing": ["document.found", D, /neither location served the document/],
  "location-1-redirects": ["document.found", D, /location 2 serves the document, but location 1 answered with a redirect \(301\)/],
  "location-1-forbidden": ["document.fallback", D, /location 1 answered with status 403; a peer stops there/],
  "location-1-tls": ["document.tls", D, /location 1 \(https:\/\/example\.org\/\.well-known\/alp\.json\) answered with a certificate that did not validate \(CERT_HAS_EXPIRED\)/],
  "location-1-tls-location-2-serves": ["document.found", D, /location 2 serves the document, but location 1 answered with a certificate that did not validate \(CERT_HAS_EXPIRED\)/],
  "location-1-tls-location-2-busy": ["document.found", D, /location 1 \(https:\/\/example\.org\/\.well-known\/alp\.json\) answered with a certificate that did not validate \(CERT_HAS_EXPIRED\), which stops a peer there/],
  "location-2-tls": ["document.found", D, /so a peer goes on to location 2 \(https:\/\/alp\.example\.org\/\.well-known\/alp\.json\), which answered with a certificate that did not validate \(CERT_HAS_EXPIRED\)/],
  "document-text-type": ["document.content-type", D, /"text\/plain"/],
  "document-oversize": ["document.size", D, /the document is 7\d{4} bytes/],
  "document-huge": ["document.size", D, /over 256 KiB/],
  "document-extra-member": ["document.schema", D, /additional properties \(policy\)/],
  "document-wrong-domain": ["document.domain-matches", D, /`domain` is "example\.net"/],
  "document-duplicate-ids": ["document.unique-ids", D, /more than one entry has the id https:\/\/broker\.example\.org/],
  "document-two-wildcards": ["document.one-wildcard", D, /2 entries have "principals": "\*"/],
  "document-overlap": ["document.no-overlap", D, /alp:guest@example\.org \(https:\/\/broker\.example\.org, https:\/\/hosted\.example\.net\)/],
  "document-foreign-address": ["document.addresses-on-domain", D, /alp:pat@partner\.example/],
  "document-url-off-origin": ["document.urls-on-origin", D, /https:\/\/hosted\.example\.net jwks_uri: https:\/\/cdn\.example\.net/],
  "document-revoked-pinned": ["document.revoked-not-pinned", D, /revoked and still pinned: https:\/\/broker\.example\.org/],
  "jwks-missing": ["keys.served", B, /answered with status 404/],
  "jwks-text-type": ["keys.content-type", H, /"text\/plain"/],
  "jwks-oversize": ["keys.size", B, /the JWKS is 7\d{4} bytes/],
  "jwks-huge": ["keys.size", B, /over 256 KiB/],
  "jwks-private-member": ["keys.schema", B, /additional properties \(d\)/],
  "jwks-unpinned-federation": ["keys.no-unpinned-federation", B, /federation keys this domain does not pin/],
  "jkt-unpublished": ["keys.current-key-pinned", B, /stale or wrong thumbprint .* does not publish its current federation key/],
  "kid-not-thumbprint": ["keys.kid-thumbprint", H, /kid "hosted-key-1"/],
  "txt-extra-member": ["dns.txt-grammar", "_alp.example.org", /uri=https:\/\/outside\.example/],
  "txt-two-records": ["dns.txt-grammar", "_alp.example.org", /2 TXT records/],
  "txt-old-id": ["dns.txt-id-serial", "_alp.example.org", /id is 41; the document's serial is 42/],
  "prm-wrong-resource": ["signin.prm", `${B}/mcp`, /`resource` is "https:\/\/broker\.example\.org"/],
  "prm-no-authorization-servers": ["signin.prm-authorization-server", `${B}/mcp`, /`authorization_servers` is \[\]/],
  "prm-missing-send": ["signin.prm-scopes", `${B}/rest`, /`scopes_supported` is \["read"\]/],
  "as-metadata-missing": ["signin.as-metadata", B, /RFC 8414 metadata answered 404/],
  "as-wrong-issuer": ["signin.oidc-discovery", H, /`issuer` is "https:\/\/login\.example\.net"/],
  "oidc-missing": ["signin.oidc-discovery", B, /OpenID Connect discovery answered 404/],
  "pkce-plain": ["signin.pkce-s256", B, /\["S256","plain"\]/],
  "no-iss-parameter": ["signin.iss-parameter", B, /found false/],
  "no-cimd": ["signin.cimd", H, /found false/],
  "no-revocation-endpoint": ["signin.revocation", B, /found nothing/],
  "mcp-challenge-no-resource-metadata": ["binding.mcp-challenge", B, /carries no resource_metadata/],
  "rest-open": ["binding.rest-challenge", H, /answered 200 to a request with no token/],
  "inbox-version-after-schema": ["inbox.version", B, /version probe was refused with `bad_envelope`/],
  "inbox-lenient-json": ["inbox.strict-json", B, /strict-json probe was refused with `discovery_failed`/],
  "inbox-no-schema": ["inbox.schema", H, /schema probe was refused with `discovery_failed`/],
  "inbox-no-lifetime-limit": ["inbox.lifetime", B, /the lifetime probe was refused with `discovery_failed`/],
  "inbox-no-clock-check": ["inbox.created-ahead", B, /created-ahead probe was refused with `discovery_failed`/],
  "inbox-no-delegate-check": ["inbox.delegate-owner", B, /from-delegate probe was refused with `discovery_failed`/],
  "inbox-no-to-delegate-check": ["inbox.delegate-owner", B, /to-delegate probe was refused with `discovery_failed`/],
  "inbox-no-expiry-order": ["inbox.lifetime", H, /expiry-order probe was refused with `discovery_failed`/],
  "inbox-accepts-unknown-domains": ["inbox.unknown-sender-domain", B, /answered 200, which is not a refusal/],
  "inbox-flat-errors": ["inbox.error-shape", B, /the body has no `error` object/],
  "inbox-wrong-status": ["inbox.error-shape", B, /422, but the registry's status for `bad_envelope` is 400/],
  "inbox-error-with-receipt": ["inbox.error-shape", H, /carries a receipt/],
  "inbox-no-retry-after": ["inbox.retry-after", B, /no Retry-After on the answer to: the unknown-sender-domain probe \(503\)/],
};

// The same faults with --broker pointed at broker.example.org: the checks that need a domain are skipped, and the
// rest fail as they do for the domain. Faults that touch only the document or the other broker change nothing.
const BROKER_ARGS = ["--broker", B, "--mcp", `${B}/mcp`, "--rest", `${B}/rest`, "--inbox", `${B}/federation/inbox`, "--jwks", `${B}/.well-known/jwks.json`];
const NEEDS_DOMAIN = (id) => id.startsWith("document.") || id.startsWith("dns.") || id === "keys.current-key-pinned" || id === "keys.no-unpinned-federation";
const ONLY_OTHER_BROKER = new Set(["kid-not-thumbprint"]);

/** Checks a fault leaves undecided ("could not decide"), because the answer may be the checker's own network or temporary. */
export const UNDECIDED = {
  // The 503 `discovery_failed` with a flat body is no ALP error, so the unknown-sender probe can't be judged.
  "inbox-flat-errors": ["inbox.unknown-sender-domain"],
};

/** Checks a fault makes skip because the inbox answers unsigned requests with 401 (Section 12.2.2). None does. */
export const SKIPPED_SIGNED = {};

/** For each variant, the checks it is expected to leave undecided, and the recommended checks it makes warn. */
export const VARIANT_EXPECT = {
  "location-1-server-error": { undecided: ["document.found", "document.fallback"] },
  "location-1-busy": { undecided: ["document.found", "document.fallback"] },
  // A refused connection may be the checker's own network: undecided, unlike a certificate that does not validate.
  "location-1-refused": { undecided: ["document.found", "document.fallback"] },
  // A TLS failure that is not a certificate failure may be the checker's own network: undecided, document.tls too.
  "location-1-tls-handshake": { undecided: ["document.found", "document.fallback", "document.tls"] },
  // An inbox that answers every unsigned probe 401, in any form, skips the probe checks and inbox.error-shape
  // (Section 12.2.2); nothing is undecided, so a broker that is otherwise fine exits 0.
  "inbox-requires-signed-requests": { skippedSigned: [...PROBES, "inbox.error-shape"] },
  "inbox-signed-requests-plain-401": { skippedSigned: [...PROBES, "inbox.error-shape"] },
  // A 401 to one probe while the same inbox judged the others is no Section 12.2.2 gate: that probe is undecided.
  "inbox-401-on-unknown-sender": { undecided: ["inbox.unknown-sender-domain"] },
  "inbox-rate-limited": { undecided: PROBES },
  "inbox-behind-busy-proxy": { undecided: PROBES },
  "metadata-rate-limited": { undecided: ["keys.served", "signin.prm"] },
  "as-metadata-rate-limited": { undecided: ["signin.as-metadata", "signin.oidc-discovery"] },
  // A 500 is a server error a peer retries (Section 10.2), so it is undecided in every family, as 502 to 504 are.
  "metadata-server-error": { undecided: ["keys.served", "signin.as-metadata", "signin.oidc-discovery"] },
  "inbox-internal-error": { undecided: PROBES },
  "endpoints-unavailable": { undecided: ["binding.mcp-challenge", "binding.rest-challenge"] },
  // Nothing can be decided: the run must say so, and exit 4, not 0.
  "everything-unavailable": { undecided: ["document.found", "document.fallback"] },
  "brokers-unavailable": { undecided: ["keys.served", "signin.prm", "binding.mcp-challenge", "binding.rest-challenge", ...PROBES] },
  // Under the reading alp-check applies, the old key is unpinned while still published: a warning, never a failure.
  "rotation-old-key-unpinned": { warn: ["keys.no-unpinned-federation"] },
};

export async function runOn(faults, args = ["example.org"]) {
  const fake = createFakeBroker({ faults });
  const run = await runChecks(parseArgs(args), { fetch: fake.fetch, resolveTxt: fake.resolveTxt });
  return { run, fake };
}

const SIGNED_REASON = "this inbox answers unsigned requests with 401; Section 12.2.2 lets a broker require signed requests, and alp-check does not sign requests";
const skippedSignedIds = (run) => [...new Set(run.results.filter((r) => r.result === "skip" && r.reason === SIGNED_REASON).map((r) => r.id))].sort();
const badIds = (run) => [...new Set(run.results.filter((r) => r.result === "fail" || (r.result === "warn" && !r.inconclusive)).map((r) => r.id))].sort();
const undecidedIds = (run) => [...new Set(run.results.filter((r) => r.inconclusive).map((r) => r.id))].sort();
const noCheckerErrors = (run, undecided = []) => {
  for (const r of run.results) assert.ok(r.result !== "error" && !String(r.message ?? "").startsWith("alp-check error"), `${r.id}: ${r.message}`);
  assert.deepEqual(undecidedIds(run), [...undecided].sort(), "checks that could not decide");
};

test("every check passes on the correct fake, for every subject", async () => {
  const { run } = await runOn([]);
  noCheckerErrors(run, []);
  const notPass = run.results.filter((r) => r.result !== "pass");
  assert.deepEqual(notPass.map((r) => `${r.id} ${r.subject}: ${r.result} ${r.reason ?? r.message ?? ""}`), []);
  assert.deepEqual([...new Set(run.results.map((r) => r.id))].sort(), CHECKS.map((c) => c.id).sort());
  assert.equal(exitCode(run), 0);
});

for (const variant of Object.keys(VARIANTS)) {
  test(`a variant the specification allows gets no failure: ${variant}`, async () => {
    const want = VARIANT_EXPECT[variant] ?? {};
    const { run } = await runOn([variant]);
    noCheckerErrors(run, want.undecided ?? []);
    assert.ok(!run.results.some((r) => r.result === "fail"), JSON.stringify(run.results.filter((r) => r.result === "fail").map((r) => `${r.id} ${r.subject}: ${r.message}`)));
    assert.deepEqual(badIds(run), [...(want.warn ?? [])].sort());
    assert.deepEqual(skippedSignedIds(run), [...(want.skippedSigned ?? [])].sort(), "checks skipped because the inbox requires signed requests");
    // 0 only when no required check was left undecided; 4 when one was.
    const requiredUndecided = (want.undecided ?? []).some((id) => CHECKS.find((c) => c.id === id).level === "required");
    assert.equal(exitCode(run), requiredUndecided ? 4 : 0);
  });
}

test("every fault has an expectation, and every expectation a fault", () => {
  assert.deepEqual(Object.keys(EXPECT).sort(), Object.keys(FAULTS).sort());
});

test("every fault has a detail, and every detail names a check the fault makes fail or warn", () => {
  assert.deepEqual(Object.keys(DETAIL).sort(), Object.keys(FAULTS).sort());
  for (const [fault, [id]] of Object.entries(DETAIL)) assert.ok(EXPECT[fault].includes(id), `${fault}: ${id}`);
});

for (const [fault, expected] of Object.entries(EXPECT)) {
  test(`fault ${fault} makes exactly ${expected.join(", ")} fail or warn, for the right subject and reason`, async () => {
    const { run } = await runOn([fault]);
    noCheckerErrors(run, UNDECIDED[fault] ?? []);
    assert.deepEqual(badIds(run), [...expected].sort());
    assert.deepEqual(skippedSignedIds(run), [...(SKIPPED_SIGNED[fault] ?? [])].sort(), "checks skipped because the inbox requires signed requests");
    const [id, subject, fragment] = DETAIL[fault];
    const hit = run.results.find((r) => r.id === id && r.subject === subject && (r.result === "fail" || r.result === "warn"));
    assert.ok(hit, `${fault}: no failing ${id} for ${subject}`);
    assert.match(hit.message ?? "", fragment, `${fault}: ${id} failed for another reason`);
    if (!ONLY_OTHER_BROKER.has(fault)) {
      const inBrokerMode = await runOn([fault], BROKER_ARGS);
      const want = expected.filter((x) => !NEEDS_DOMAIN(x));
      noCheckerErrors(inBrokerMode.run, (UNDECIDED[fault] ?? []).filter((x) => !NEEDS_DOMAIN(x)));
      assert.deepEqual(badIds(inBrokerMode.run), [...want].sort(), `${fault} in --broker mode`);
      if (want.includes(id)) {
        const where = subject.startsWith(B) ? subject : B;
        const again = inBrokerMode.run.results.find((r) => r.id === id && r.subject === where && (r.result === "fail" || r.result === "warn"));
        assert.ok(again && fragment.test(again.message ?? ""), `${fault} in --broker mode: ${id}`);
      }
    }
    for (const r of run.results.filter((x) => expected.includes(x.id) && x.result !== "pass" && x.result !== "skip")) {
      const c = CHECKS.find((k) => k.id === r.id);
      assert.equal(r.result, c.level === "required" ? "fail" : "warn", r.id);
    }
    const requiredFailed = expected.some((id) => CHECKS.find((c) => c.id === id).level === "required");
    const requiredUndecided = (UNDECIDED[fault] ?? []).some((id) => CHECKS.find((c) => c.id === id).level === "required");
    assert.equal(exitCode(run), requiredFailed ? 1 : requiredUndecided ? 4 : 0);
  });
}

test("every check in the catalogue fails or warns under at least one fault", () => {
  const covered = new Set(Object.values(EXPECT).flat());
  const missing = CHECKS.map((c) => c.id).filter((id) => !covered.has(id));
  assert.deepEqual(missing, []);
});

test("an inbox that answers every unsigned probe 401 gets its probe checks and inbox.error-shape skipped, whatever the 401's form", async () => {
  for (const variant of ["inbox-requires-signed-requests", "inbox-signed-requests-plain-401"]) {
    const { run } = await runOn([variant]);
    for (const id of [...PROBES, "inbox.error-shape"]) {
      for (const subject of [B, H]) {
        const r = run.results.find((x) => x.id === id && x.subject === subject);
        assert.equal(r.result, "skip", `${variant}: ${id} ${subject}`);
        assert.equal(r.reason, SIGNED_REASON, `${variant}: ${id} ${subject}`);
      }
    }
    assert.equal(exitCode(run), 0, variant);
  }
});

test("a 401 to one probe while the same inbox judged the others is undecided, and inbox.error-shape notes it without judging it", async () => {
  const { run } = await runOn(["inbox-401-on-unknown-sender"]);
  const r = run.results.find((x) => x.id === "inbox.unknown-sender-domain" && x.subject === B);
  assert.equal(r.result, "warn");
  assert.equal(r.inconclusive, true);
  assert.match(r.message, /answered this probe with 401 while other unsigned probes to the same inbox were judged/);
  const shape = run.results.find((x) => x.id === "inbox.error-shape" && x.subject === B);
  assert.equal(shape.result, "pass");
  assert.ok((shape.notes ?? []).some((n) => /the unknown-sender-domain probe: 401, not judged/.test(n)), JSON.stringify(shape.notes));
  // The PASS line itself says what it did not judge, in the text report and in the JSON.
  assert.equal(shape.not_judged, "1 answer with 401 (the unknown-sender-domain probe), since Section 12.2.2 gives no form for refusing an unsigned request");
  const text = toText(run).replace(/\n +/g, " ");
  assert.match(text, /PASS {2}inbox\.error-shape \[https:\/\/broker\.example\.org\][^]*?: Every refusal[^]*?\. Not judged: 1 answer with 401 \(the unknown-sender-domain probe\)/);
  assert.equal(toJson(run).results.find((x) => x.id === "inbox.error-shape" && x.subject === B).not_judged, shape.not_judged);
  // With no 401 answer, the line carries nothing extra.
  const clean = (await runOn([])).run.results.find((x) => x.id === "inbox.error-shape" && x.subject === B);
  assert.equal(clean.not_judged, undefined);
  for (const id of PROBES.filter((x) => x !== "inbox.unknown-sender-domain")) assert.equal(run.results.find((x) => x.id === id && x.subject === B).result, "pass", id);
  assert.equal(exitCode(run), 4);
});
