// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { displayAddress, delegateBelongsTo, domainOf, parseAddress } from "./address.ts";
import { sanitizeText } from "./content.ts";
import { DevIdentityVerifier } from "./identity.ts";
import { PROTOCOL } from "./protocol.ts";
import { buildSecurityEvent } from "./security-events.ts";
import { schemaErrors } from "./spec-schemas.ts";

test("addresses: protocol form, case folding, delegates", () => {
  assert.equal(parseAddress("Ana@Example.org"), "alp:ana@example.org");
  assert.equal(parseAddress("alp:ana@example.org"), "alp:ana@example.org");
  assert.throws(() => parseAddress("ana+tag@example.org"));
  assert.throws(() => parseAddress("ana@localhost"));
  assert.throws(() => parseAddress("a..b@example.org"));
  assert.equal(displayAddress("alp:ana@example.org"), "ana@example.org");
  assert.equal(domainOf("alp:ana@example.org"), "example.org");
  assert.equal(delegateBelongsTo("alp:ana@example.org/muse", "alp:ana@example.org"), true);
  assert.equal(delegateBelongsTo("alp:lee@example.org/muse", "alp:ana@example.org"), false);
  assert.equal(PROTOCOL.addressScheme, "alp:");
});

test("delivered free text (spec 12.1.6): tags stripped, URLs defanged, invisible characters removed", () => {
  assert.equal(sanitizeText("<script>x</script>**bold**"), "x**bold**");
  assert.equal(sanitizeText("see https://evil.example/path"), "see hxxps://evil[.]example/path");
  assert.equal(sanitizeText("a < b and c > d"), "a < b and c > d");
  assert.equal(sanitizeText("zero\u200bwidth \u202eflip"), "zerowidth flip");
});

test("the dev identity provider binds to a stable iss + sub and can require a per-session secret", async () => {
  const idp = new DevIdentityVerifier([{ username: "ana", address: "ana@example.org", display_name: "Ana" }], { secret: "s3cret-session" });
  const id = await idp.verify({ kind: "dev", username: "Ana", secret: "s3cret-session" });
  assert.equal(id.address, "alp:ana@example.org");
  assert.equal(id.sub, "dev-ana");
  await assert.rejects(idp.verify({ kind: "dev", username: "ana", secret: "wrong" }), /secret/);
  await assert.rejects(idp.verify({ kind: "dev", username: "nobody", secret: "s3cret-session" }), /unknown/);
});

test("security events validate against the spec and map to OCSF classes", () => {
  const e = buildSecurityEvent({ uid: "01JC0000000000000000000000", at: new Date("2026-11-09T14:00:00Z"), event: "token_issued", broker: "https://broker.example.org", failed: false, details: { client_id: "https://connector.example/client-metadata.json" } });
  assert.equal(e.class_uid, 3002);
  assert.equal(e.type_uid, 300201);
  assert.deepEqual(schemaErrors("securityEvent", e), []);
  assert.equal(e.metadata.product.vendor_name, PROTOCOL.name, "the vendor is the project, not a company");
  const f = buildSecurityEvent({ uid: "01JC0000000000000000000001", at: new Date(), event: "signature_failure", broker: "https://broker.example.org", failed: true });
  assert.equal(f.class_uid, 6003);
  assert.equal(f.severity_id, 4);
});
