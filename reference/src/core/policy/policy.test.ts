// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { examplePolicy, ANA, FRAN, LEE, PAT } from "../../demo/world.ts";
import { ScopeRegistry } from "../scopes/index.ts";
import { effectiveTerms, namesExplicitly } from "../relationships.ts";
import type { RelationshipGrant } from "../types.ts";
import { SampleDlp, refuseUnconnectedDlpHook, runDlp } from "./dlp.ts";
import { evaluateMessage, codeForSender } from "./evaluate.ts";
import { blockedBy, checkOrgPolicy, deliveryConstraints, domainPatternMatches, federationAllows, findDefault, labelMatches, meetsConstraints, refMatches } from "./org-policy.ts";

const now = new Date("2026-11-09T14:00:00.000Z");
const policy = checkOrgPolicy(examplePolicy(now));
const reg = ScopeRegistry.load();
const briefing = reg.require("alp.briefing/1");

test("principal refs, labels and domain patterns", () => {
  assert.equal(refMatches(policy, "@org", LEE), true);
  assert.equal(refMatches(policy, "@org", PAT), false);
  assert.equal(refMatches(policy, "group:finance", FRAN), true);
  assert.equal(refMatches(policy, "group:finance", LEE), false);
  assert.equal(refMatches(policy, "alp:*@partner.example", PAT), true);
  assert.equal(refMatches(policy, "*", PAT), true);
  assert.equal(labelMatches("confidential.*", "confidential"), true);
  assert.equal(labelMatches("confidential.*", "confidential.financial"), true);
  assert.equal(labelMatches("confidential.*", "internal"), false);
  assert.equal(domainPatternMatches("*.example.com", "a.example.com"), true);
  assert.equal(domainPatternMatches("*.example.com", "example.com"), false);
  assert.equal(federationAllows(policy, "blocked.example"), false);
  assert.equal(federationAllows(policy, "partner.example"), true);
});

test("default relationships unite forward and reverse terms for in-org pairs", () => {
  const d = findDefault(policy, ANA, LEE, "alp.briefing/1");
  assert.ok(d?.direction.may.includes("request") && d.direction.may.includes("inform"));
  assert.equal(findDefault(policy, ANA, PAT, "alp.briefing/1"), null);
});

test("effective terms: consent grant, narrowing, revoked, defaults", () => {
  const base: Omit<RelationshipGrant, "basis" | "scopes" | "status"> = {
    alp: "0.1", id: "01JC0000000000000000000001", principal: LEE, principal_id: "lee-principal-00001", counterparty: ANA,
    created_at: now.toISOString(), updated_at: now.toISOString(), sealed: { by: "lee-principal-00001", method: "reauth-dev", at: now.toISOString() },
  };
  const def = effectiveTerms({ owner: LEE, counterparty: ANA, scope: "alp.briefing/1", direction: "inbound", grant: null, policy, now });
  assert.equal(def.ok && def.terms.source, "default");
  const narrowing: RelationshipGrant = { ...base, basis: "narrowing", status: "active", scopes: { "alp.availability/1": { may: ["request"], disclose: [], receive: ["/body/window"], commit: "ask_me", redaction: "reject" } } };
  assert.deepEqual(effectiveTerms({ owner: LEE, counterparty: ANA, scope: "alp.briefing/1", direction: "inbound", grant: narrowing, policy, now }), { ok: false, code: "no_relationship", revoked: false });
  const n = effectiveTerms({ owner: LEE, counterparty: ANA, scope: "alp.availability/1", direction: "inbound", grant: narrowing, policy, now });
  assert.ok(n.ok && n.terms.source === "narrowed" && n.terms.fieldSets.length === 2);
  const revoked: RelationshipGrant = { ...narrowing, status: "revoked" };
  assert.deepEqual(effectiveTerms({ owner: LEE, counterparty: ANA, scope: "alp.availability/1", direction: "inbound", grant: revoked, policy, now }), { ok: false, code: "no_relationship", revoked: true });
  const rev = { principal: LEE, counterparty: ANA, scopes: ["*"] as ["*"], reason: "x", effective_at: now.toISOString(), received_at: now.toISOString() };
  assert.equal(effectiveTerms({ owner: LEE, counterparty: ANA, scope: "alp.briefing/1", direction: "outbound", grant: null, revocation: rev, policy, now }).ok, false);
});

test("free text must be named at least as deep as the field", () => {
  assert.equal(namesExplicitly(["/body/topic"], "/body/topic", "/body/topic"), true);
  assert.equal(namesExplicitly(["/body"], "/body/topic", "/body/topic"), false);
  assert.equal(namesExplicitly(["/body/questions/*"], "/body/questions/*", "/body/questions/2"), true);
  assert.equal(namesExplicitly(["/body/context"], "/body/context/project", "/body/context/project"), false);
  assert.equal(namesExplicitly(["/body/questions"], "/body/questions/*", "/body/questions/0"), false, "spec 6.5: exactly as many tokens");
  assert.equal(namesExplicitly(["/note"], "/note", "/note"), true);
});

test("the evaluator: allow, unclassified and undisclosed fields, inbound never redacts, codes to the sender stay generic", async () => {
  const terms = { source: "grant" as const, ref: "grant:x", may: ["request" as const], fieldSets: [["/body/topic", "/body/depth"]], commit: "ask_me" as const, redaction: "redact" as const };
  const common = { owner: ANA, owner_id: "ana-principal-00001", counterparty: LEE, scope: briefing, type: "request" as const, terms, policy, dlp: new SampleDlp(), limits: { noteMaxChars: 280, bodyMaxBytes: 65536 } };
  const ok = await evaluateMessage({ ...common, direction: "outbound", body: { topic: "T", depth: "summary" } });
  assert.equal(ok.outcome, "allow");
  assert.deepEqual(ok.disclosed, ["/body/topic", "/body/depth"]);
  const red = await evaluateMessage({ ...common, direction: "outbound", body: { topic: "T", depth: "summary", due_by: "2026-11-10T00:00:00Z" } });
  assert.equal(red.outcome, "redact");
  assert.deepEqual(red.redacted, ["/body/due_by"]);
  const inbound = await evaluateMessage({ ...common, direction: "inbound", owner: LEE, counterparty: ANA, body: { topic: "T", depth: "summary", due_by: "2026-11-10T00:00:00Z" } });
  assert.equal(inbound.outcome, "reject");
  assert.equal(codeForSender(inbound.reasons), "not_accepted");
  const wrongType = await evaluateMessage({ ...common, direction: "outbound", type: "inform", body: { points: ["x"], as_of: "2026-11-09T14:00:00Z" } });
  assert.equal(wrongType.code, "type_not_allowed");
});

test("DLP: the sample hook, timeouts fail closed, and on_error allow is honored", async () => {
  const dlp = new SampleDlp();
  const input = { principal_id: "p".repeat(16), principal: ANA, counterparty: LEE, direction: "outbound" as const, scope: "alp.briefing/1", labels: [], pointer: "/note", text: "" };
  assert.equal((await dlp.check({ ...input, text: "card 4111 1111 1111 1111" })).verdict, "block");
  assert.equal((await dlp.check({ ...input, text: "AKIAABCDEFGHIJKLMNOP" })).verdict, "block");
  assert.equal((await dlp.check({ ...input, text: "ssn 123-45-6789" })).verdict, "block");
  assert.equal((await dlp.check({ ...input, text: "meet at 4111" })).verdict, "allow");
  const slow = { id: "slow", check: () => new Promise<never>(() => {}) };
  assert.equal((await runDlp(slow, input, { timeoutMs: 20 })).verdict, "block");
  assert.equal((await runDlp(slow, input, { timeoutMs: 20, onError: "allow" })).verdict, "allow");
});

test("npm start connects no outside DLP service, so it refuses a policy whose dlp.hook names one", () => {
  assert.equal(refuseUnconnectedDlpHook(policy, "policy.json"), policy);
  const named = checkOrgPolicy(examplePolicy(now, { dlp: { hook: "purview", categories: ["payment_card"], inbound: true } }));
  assert.throws(() => refuseUnconnectedDlpHook(named, "policy.json"), /^Error: policy\.json: dlp\.hook names an outside DLP service/);
});

test("kill switches, delivery minimums and constraints", () => {
  const p = checkOrgPolicy(examplePolicy(now, { serial: 2, blocked: { domains: ["*.bad.example"], client_ids: ["c1"] } }));
  assert.equal(blockedBy(p, { domains: ["x.bad.example"] }), "blocked:domain");
  assert.equal(blockedBy(p, { client_id: "c1" }), "blocked:client");
  assert.equal(blockedBy(p, { domains: ["good.example"] }), null);
  const c = deliveryConstraints(policy, ["confidential"]);
  assert.deepEqual(c, { deliver_to: { min_class: "business" } });
  assert.equal(meetsConstraints(c, { attestation: "self", class: "consumer" }, false), false);
  assert.equal(meetsConstraints(c, { attestation: "vendor", class: "business" }, false), true);
  assert.equal(meetsConstraints({ no_training: true }, { attestation: "tenant", class: "enterprise" }, false), false);
});
