// SPDX-License-Identifier: FSL-1.1-ALv2
// What a refusal tells the agent that sent the draft (spec 18.3): enough to fix it. Each schema problem is described
// from the schema (allowed values, expected type, the date-time form, bounds, missing and unknown fields), every reason
// is joined into the message within 1,000 characters, a field the scope doesn't define is named as such with the
// fields it does define, and organization rules and message types are named for what they are. Codes and pointers
// don't change, and no submitted value is ever echoed: refusal reasons go to the sender's ledger (spec 6.6).

import assert from "node:assert/strict";
import { test } from "node:test";
import { ANA, LEE, buildWorld, examplePolicy } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { DelegateCaller, OrgPolicy } from "../core/types.ts";
import { BindingState } from "../oauth/state.ts";
import type { AuthContext } from "../oauth/resource.ts";
import { runTool } from "./handlers.ts";
import type { ToolContext, ToolOutcome } from "./handlers.ts";
import { toolCatalog } from "./tools.ts";

type Refusal = { code: string; message: string; pointers?: string[]; rule?: string };

function refused(o: ToolOutcome, code: string): Refusal & { text: string } {
  assert.equal(o.ok, false, JSON.stringify(o));
  if (o.ok) throw new Error("unreachable");
  const err = o.structured?.["error"] as Refusal | undefined;
  assert.ok(err, "a structured error");
  assert.equal(err.code, code, o.text);
  assert.ok(err.message.length <= 1000, `message within 1,000 characters (${err.message.length})`);
  assert.deepEqual(toolCatalog().validateOutput("alp_send", o.structured), [], "the error matches tools.json");
  return { ...err, text: o.text };
}

async function agentOf(w: World, address: string, caller: DelegateCaller): Promise<(tool: string, args: Record<string, unknown>) => Promise<ToolOutcome>> {
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const p = (await w.example.getPrincipal(address))!;
  const auth: AuthContext = { caller, principal_id: p.principal_id, scopes: ["read", "send"], via: "oauth", resource: "mcp" };
  return (tool, args) => runTool(ctx, auth, tool, args);
}

const WINDOW = { start: "2026-11-10T09:00:00Z", end: "2026-11-10T17:00:00Z" };
const avail = (body: Record<string, unknown>) => ({ to: "lee@example.org", scope: "alp.availability/1", type: "request", body });
const brief = (body: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ to: "lee@example.org", scope: "alp.briefing/1", type: "request", body, ...extra });

test("schema_invalid: each problem is described from the schema, and every one is in the message", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);

  const e = refused(await ana("alp_send", brief({ topic: "Q4", depth: "verbose", due_by: "next Friday" })), "schema_invalid");
  assert.deepEqual(e.pointers, ["/body/depth", "/body/due_by"], "the pointers are unchanged");
  assert.match(e.message, /\/body\/depth must be one of "headline", "summary", "detailed"\./, "an enum lists the allowed values");
  assert.match(e.message, /\/body\/due_by must be an RFC 3339 date-time in UTC with seconds, e\.g\. 2026-11-10T14:00:00Z\./, "a date-time says which form");
  assert.match(e.text, /alp_whoami with include_scopes returns the schemas/);

  const type = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: "30" })), "schema_invalid");
  assert.match(type.message, /\/body\/duration_minutes must be an integer\./, "a type error names the type");
  const low = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: 3 })), "schema_invalid");
  assert.match(low.message, /\/body\/duration_minutes must be at least 5\./);
  const high = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: 600 })), "schema_invalid");
  assert.match(high.message, /\/body\/duration_minutes must be at most 480\./);
  const missing = refused(await ana("alp_send", avail({ window: { start: WINDOW.start }, duration_minutes: 30 })), "schema_invalid");
  assert.match(missing.message, /\/body\/window\/end is required and missing\./, "required names the missing field");
  const many = refused(await ana("alp_send", brief({ topic: "x".repeat(201), depth: "summary", questions: ["a", "b", "c", "d", "e", "f"] })), "schema_invalid");
  assert.match(many.message, /\/body\/topic must be at most 200 characters long\./);
  assert.match(many.message, /\/body\/questions must have at most 5 items\./);
});

test("an unknown field between one person's own agents (no coverage step) names the field and the fields allowed there", async () => {
  const w = await buildWorld({ domainDocs: false });
  await w.example.registerDelegate({ principal: ANA, label: "helper", kind: "bridged", client_id: w.ana.agent.client_id });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const e = refused(await ana("alp_send", { to: "ana@example.org", to_delegate: "helper", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration: 30 } }), "schema_invalid");
  assert.match(e.message, /\/body\/duration isn't a field here \(fields: window, duration_minutes, timezone, purpose\)\./);
  assert.match(e.message, /\/body\/duration_minutes is required and missing\./);
});

test("not_disclosed for a name the scope doesn't define: the fields it does define, a guess, the draft's other schema problems, and advice to fix it", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const e = refused(await ana("alp_send", avail({ window: { start: "2026-11-10T09:00", end: WINDOW.end }, duration: 30 })), "not_disclosed");
  assert.deepEqual(e.pointers, ["/body/duration"], "the code and pointers stay those of S5");
  assert.ok(e.message.startsWith("/body/duration isn't a field of alp.availability/1 request (fields: window, duration_minutes, timezone, purpose); did you mean duration_minutes?"), e.message);
  assert.match(e.message, /The draft also doesn't match the schema: \/body\/duration_minutes is required and missing; \/body\/window\/start must be an RFC 3339 date-time/);
  assert.match(e.text, /Use the field names the scope defines/);
  assert.doesNotMatch(e.text, /don't move it into another field/, "the advice is to fix the name, not to leave the field out");

  // A misspelled parent: named once, with its closest field.
  const typo = refused(await ana("alp_send", avail({ windw: { start: WINDOW.start, end: WINDOW.end }, duration_minutes: 30 })), "not_disclosed");
  assert.deepEqual(typo.pointers, ["/body/windw/end", "/body/windw/start"]);
  assert.equal(typo.message.split("isn't a field").length, 2, typo.message);
  assert.match(typo.message, /did you mean window\?/);
});

test("not_disclosed for a field the terms leave out, and for free text they don't name: what the terms are, and what to do", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const left = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: 30, purpose: "meeting" })), "not_disclosed");
  assert.ok(left.message.startsWith("Your person's terms for alp.availability/1 with lee@example.org don't include /body/purpose. "), left.message);
  assert.match(left.text, /Leave it out; don't move it into another field\./);

  const text = refused(await ana("alp_send", brief({ topic: "Q4", depth: "summary", context: { project: "Atlas" } })), "not_disclosed");
  assert.ok(text.message.startsWith("Your person's terms for alp.briefing/1 with lee@example.org don't name the free-text field /body/context/project: send without it, or ask your person to allow it on their broker page. "), text.message);
  const note = refused(await ana("alp_send", brief({ topic: "Q4", depth: "summary" }, { note: "fyi" })), "not_disclosed");
  assert.match(note.message, /don't name the free-text field \/note: send without it/);

  // Both kinds at once: one sentence each, and mixed advice.
  const both = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: 30, purpose: "meeting", length: 30 })), "not_disclosed");
  assert.match(both.message, /\/body\/length isn't a field of alp\.availability\/1 request/);
  assert.match(both.message, /don't include \/body\/purpose\./);
  assert.match(both.text, /Correct the names the scope doesn't define; leave out the fields your person's terms don't allow/);
});

test("org_policy names the organization's rule; type_not_allowed names the type, scope and counterparty and points to alp_contacts", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const org = refused(await ana("alp_send", brief({ topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } })), "org_policy");
  assert.ok(org.message.startsWith("Your organization's rule financial-stays-in-finance keeps /body/context/amount/currency and /body/context/amount/value from lee@example.org. "), org.message);
  assert.equal(org.rule, "financial-stays-in-finance");
  assert.doesNotMatch(org.text, /your person's rules/);

  // Ana may only send `request` in alp.availability/1 to Lee (the organization's default); an ask_human in her thread isn't.
  const sent = await ana("alp_send", avail({ window: WINDOW, duration_minutes: 30 }));
  assert.equal(sent.ok, true, sent.text);
  const thread = sent.ok ? String(sent.structured["thread"]) : "";
  const t = refused(await ana("alp_send", { to: "lee@example.org", scope: "alp.availability/1", type: "ask_human", thread, body: { urgency: "normal", reason: "needs_decision" } }), "type_not_allowed");
  assert.match(t.message, /^Your person's terms for alp\.availability\/1 with lee@example\.org don't allow ask_human messages\./);
  assert.match(t.text, /alp_contacts lists the types you may send each contact\./);
});

test("federation_blocked, body_too_large and dlp_blocked each say what the sender's own side refused, never the value", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const fed = refused(await ana("alp_send", { to: "x@blocked.example", scope: "alp.briefing/1", type: "request", body: { topic: "Q4", depth: "summary" } }), "federation_blocked");
  assert.equal(fed.message, "Your organization doesn't exchange messages with blocked.example. Tell your person: their organization's administrator decides which domains it exchanges messages with.");
  const big = refused(await ana("alp_send", brief({ topic: "Q4", depth: "summary", questions: ["x".repeat(70_000)] })), "body_too_large");
  assert.ok(big.message.startsWith("The body is larger than 65536 bytes as canonical JSON. Send the corrected draft with a new idempotency_key"), big.message);
  const card = refused(await ana("alp_send", brief({ topic: "pay with 4111 1111 1111 1111", depth: "summary" })), "dlp_blocked");
  assert.equal(card.message, "/body/topic looks like sensitive data (payment_card). Leave that text out; don't rephrase it or move it into another field.");
  assert.deepEqual(card.pointers, ["/body/topic"]);
  assert.ok(!card.text.includes("4111"), "the matched text isn't echoed");
});

test("a long refusal stays within 1,000 characters and says how many reasons it left out", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const lee = await agentOf(w, LEE, w.lee.agent);
  const ask = await ana("alp_send", avail({ window: WINDOW, duration_minutes: 30 }));
  assert.equal(ask.ok, true, ask.text);
  if (!ask.ok) return;
  const free = Array.from({ length: 40 }, (_, i) => ({ start: `day ${i}`, end: `day ${i} later` }));
  const e = refused(await lee("alp_send", { to: "ana@example.org", scope: "alp.availability/1", type: "inform", thread: ask.structured["thread"], in_reply_to: ask.structured["id"], body: { free, as_of: "now" } }), "schema_invalid");
  assert.ok(e.message.length <= 1000);
  assert.match(e.message, /\(and \d+ more\) The body doesn't match the scope's schema \(see pointers\)\. alp_whoami with include_scopes returns the schemas\. Send the corrected draft with a new idempotency_key if you set one \(the same key returns this answer for 24 hours\)\.$/, "the advice still fits after the reasons");
  assert.equal(e.pointers?.length, 64, "pointers keep their own limit");
});

test("type_not_allowed between one person's own agents says the negotiation types need two people and points to alp_whoami", async () => {
  const w = await buildWorld({ domainDocs: false });
  const d = await w.example.registerDelegate({ principal: ANA, label: "helper", kind: "bridged", client_id: w.ana.agent.client_id });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const helper = await agentOf(w, ANA, { kind: "delegate", principal: ANA, delegate: d.id, client_id: w.ana.agent.client_id });
  const req = await ana("alp_send", { to: "ana@example.org", to_delegate: "helper", scope: "alp.meeting/1", type: "request", body: { title: "Sync", window: { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" }, duration_minutes: 30 } });
  assert.equal(req.ok, true, req.text);
  if (!req.ok) return;
  const e = refused(await helper("alp_send", { to: "ana@example.org", to_delegate: "muse", scope: "alp.meeting/1", type: "propose", thread: req.structured["thread"], in_reply_to: req.structured["id"], body: { title: "Sync", duration_minutes: 30, slots: [{ start: "2026-11-10T16:00:00Z", end: "2026-11-10T16:30:00Z" }], location: { kind: "video" } } }), "type_not_allowed");
  assert.equal(e.message, "propose isn't sent between one person's own agents: propose, counter, accept and commit need two people. alp_whoami lists the scopes and types you can use with your person's other agents.");
  assert.doesNotMatch(e.text, /terms|alp_contacts/, "no terms with oneself, and alp_contacts doesn't list the person's own agents");
  // A reply that names no to_delegate goes to the agent it answers (spec 12.1.3): between own agents too, the same advice.
  const reply = refused(await helper("alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "propose", thread: req.structured["thread"], in_reply_to: req.structured["id"], body: { title: "Sync", duration_minutes: 30, slots: [{ start: "2026-11-10T16:00:00Z", end: "2026-11-10T16:30:00Z" }], location: { kind: "video" } } }), "type_not_allowed");
  assert.equal(reply.message, e.message);
});

// Refusals aren't rate limited, so what one refused draft costs must not grow with the square of its refused fields: no
// reason's text lists every other field, the message stops collecting once it is full, and the ledger entry keeps at
// most 64 reasons. Each draft here is under 64 KiB; on the code before these limits, the long member name took over a
// minute and each ledger entry held 100 MB or more.
test("a draft with thousands of refused fields gets its refusal quickly, and a ledger entry of bounded size", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const keys = (n: number): Record<string, number> => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, 0]));
  const drafts: { name: string; code: string; body: Record<string, unknown>; message: RegExp }[] = [
    { name: "an organization rule over 6,000 fields", code: "org_policy", body: { topic: "Q4", depth: "summary", context: { amount: keys(6000) } }, message: /^Your organization's rule financial-stays-in-finance keeps \/body\/context\/amount\/k0, .* and \d+ more from lee@example\.org\. / },
    { name: "4,000 fields under a name the scope doesn't define, and 4,000 schema problems", code: "not_disclosed", body: { topic: "Q4", depth: "summary", zz: keys(4000), questions: Array.from({ length: 4000 }, () => 0) }, message: /^\/body\/zz isn't a field of alp\.briefing\/1 request .* The draft also doesn't match the schema: \/body\/questions must have at most 5 items; \/body\/questions\/0 must be a string; .*\(and \d+ more\)\. / },
    { name: "a 30,000-character member name above 3,500 fields", code: "not_disclosed", body: { topic: "Q4", depth: "summary", ["q".repeat(30_000)]: keys(3500) }, message: /^\/body\/q{113}… isn't a field of alp\.briefing\/1 request \(fields: topic, questions, depth, due_by, context\)\. / },
    { name: "30,000 schema problems", code: "schema_invalid", body: { topic: "Q4", depth: "summary", questions: Array.from({ length: 30_000 }, () => 0) }, message: /^\/body\/questions must have at most 5 items\. \/body\/questions\/0 must be a string\. .*\(and \d+ more\) / },
  ];
  for (const d of drafts) {
    const before = (await w.example.ledger(w.ana.human())).filter((e) => e.kind === "refused_outbound").length;
    const t0 = performance.now();
    const e = refused(await ana("alp_send", brief(d.body)), d.code);
    const ms = performance.now() - t0;
    assert.ok(ms < 5000, `${d.name}: answered in ${ms.toFixed(0)} ms`);
    const refusals = (await w.example.ledger(w.ana.human())).filter((x) => x.kind === "refused_outbound");
    assert.equal(refusals.length, before + 1, `${d.name}: the refusal is written to the ledger (spec 6.6)`);
    const last = refusals.at(-1);
    const payload = last ? await w.example.ledgerPayload(w.ana.human(), last.seq) : null;
    const detail = (payload?.["detail"] ?? []) as { code: string; detail?: string }[];
    assert.ok(JSON.stringify(payload).length < 100_000, `${d.name}: payload of ${JSON.stringify(payload).length} characters`);
    assert.ok(detail.length <= 65, `${d.name}: ${detail.length} reasons kept`);
    assert.match(detail.at(-1)?.detail ?? "", /^\d+ more reasons, not recorded$/, `${d.name}: the rest are counted`);
    for (const r of detail) assert.ok((r.detail ?? "").length <= 1000, `${d.name}: a reason's text of ${(r.detail ?? "").length} characters`);
    assert.match(e.message, d.message, `${d.name}: ${e.message}`);
  }
});

// With redaction "redact", the fields the terms don't allow are removed and listed in decision.redacted, which takes at
// most 64 pointers of at most 512 characters (common.schema.json). A draft with more to remove is refused instead, as
// without redaction: before, the broker removed them all, signed an envelope no broker accepts (bad_envelope) and wrote
// every removed pointer into its sent entry, which for the long member name took about 18 seconds and 105 MB.
test("with redaction redact, a draft with more fields to remove than a message can list is refused quickly, and nothing is signed", async () => {
  const w = await buildWorld({ domainDocs: false });
  const fields = ["/body/topic", "/body/questions/*", "/body/depth", "/body/points/*", "/body/as_of"];
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": { may: ["request", "inform", "ask_human"], disclose: fields, receive: fields, commit: "ask_me", redaction: "redact" } } });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const keys = (n: number): Record<string, number> => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, 0]));
  const kinds = async (kind: string): Promise<number> => (await w.example.ledger(w.ana.human())).filter((e) => e.kind === kind).length;
  const drafts = [
    { name: "a 30,000-character member name above 3,500 fields", body: { topic: "Q4", depth: "summary", ["q".repeat(30_000)]: keys(3500) }, message: /^Your person's terms remove the fields they don't allow, but this draft has 3500 fields to remove, some with names over 512 characters, more than one message can list \(64, of up to 512 characters each\), so it is refused instead\. \/body\/q{113}… isn't a field of alp\.briefing\/1 request/ },
    { name: "65 fields the terms don't allow", body: { topic: "Q4", depth: "summary", zz: keys(65) }, message: /^Your person's terms remove the fields they don't allow, but this draft has 65 fields to remove, more than one message can list \(64, of up to 512 characters each\), so it is refused instead\. / },
  ];
  for (const d of drafts) {
    const [refusals, sent] = [await kinds("refused_outbound"), await kinds("sent")];
    const t0 = performance.now();
    const e = refused(await ana("alp_send", brief(d.body)), "not_disclosed");
    const ms = performance.now() - t0;
    assert.ok(ms < 5000, `${d.name}: answered in ${ms.toFixed(0)} ms`);
    assert.match(e.message, d.message, `${d.name}: ${e.message}`);
    assert.equal(await kinds("sent"), sent, `${d.name}: nothing was signed or sent`);
    assert.equal(await kinds("refused_outbound"), refusals + 1, `${d.name}: the refusal is written to the ledger (spec 6.6)`);
    const entries = await w.example.ledger(w.ana.human());
    const last = entries.filter((x) => x.kind === "refused_outbound").at(-1);
    assert.ok(JSON.stringify(last).length < 100_000, `${d.name}: an entry of ${JSON.stringify(last).length} characters`);
    const payload = last ? await w.example.ledgerPayload(w.ana.human(), last.seq) : null;
    assert.ok(JSON.stringify(payload).length < 100_000, `${d.name}: payload of ${JSON.stringify(payload).length} characters`);
    assert.match(((payload?.["detail"] ?? []) as { detail?: string }[]).at(-1)?.detail ?? "", /^\d+ more reasons, not recorded$/, `${d.name}: the rest are counted`);
  }
  // 64 or fewer: removed, listed in decision.redacted and sent, as before.
  const sent = await ana("alp_send", brief({ topic: "Q4", depth: "summary", zz: keys(64) }));
  assert.equal(sent.ok, true, sent.text);
  assert.equal(((sent.ok ? sent.structured["decision"] : {}) as { redacted?: string[] }).redacted?.length, 64);

  // The same for an organization's redact rule: what decision.redacted couldn't list, the rule refuses, as a reject rule does.
  const policy = (now: Date): OrgPolicy => {
    const p = examplePolicy(now);
    return { ...p, classification: { ...p.classification, rules: (p.classification?.rules ?? []).map((r) => (r.id === "financial-stays-in-finance" ? { ...r, action: "redact" as const } : r)) } };
  };
  const w2 = await buildWorld({ domainDocs: false, policy });
  const ana2 = await agentOf(w2, ANA, w2.ana.agent);
  const org = refused(await ana2("alp_send", brief({ topic: "Q4", depth: "summary", context: { amount: keys(65) } })), "org_policy");
  assert.match(org.message, /^Your organization's rule financial-stays-in-finance keeps \/body\/context\/amount\/k0, /);
  const removed = await ana2("alp_send", brief({ topic: "Q4", depth: "summary", context: { amount: keys(3) } }));
  assert.equal(removed.ok, true, removed.text);
  assert.deepEqual(((removed.ok ? removed.structured["decision"] : {}) as { redacted?: string[] }).redacted, ["/body/context/amount/k0", "/body/context/amount/k1", "/body/context/amount/k2"]);
});

test("a refusal names a long pointer by its start, and the error's pointers stay within tools.json", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const long = "x".repeat(600);
  const e = refused(await ana("alp_send", avail({ window: WINDOW, duration_minutes: 30, [long]: 1 })), "not_disclosed");
  assert.ok(e.message.startsWith(`/body/${"x".repeat(113)}… isn't a field of alp.availability/1 request`), e.message);
  assert.equal(e.pointers, undefined, "a pointer over 512 characters isn't listed");
});

test("no refusal echoes a submitted value: not in the message, and not in the sender's ledger", async () => {
  const w = await buildWorld({ domainDocs: false });
  const ana = await agentOf(w, ANA, w.ana.agent);
  const values = ["VERBOSE-XYZZY-1", "NEXT-FRIDAY-XYZZY-2", "UNKNOWN-XYZZY-3", "THIRTY-XYZZY-4", "ATLAS-XYZZY-5"];
  const drafts = [
    brief({ topic: "Q4", depth: values[0], due_by: values[1] }),
    avail({ window: WINDOW, duration: values[2] }),
    avail({ window: WINDOW, duration_minutes: values[3] }),
    brief({ topic: "Q4", depth: "summary", context: { project: values[4] } }),
  ];
  const texts: string[] = [];
  for (const d of drafts) {
    const o = await ana("alp_send", d);
    assert.equal(o.ok, false, o.text);
    texts.push(o.text, JSON.stringify(o.structured ?? {}));
  }
  const ledger = await w.example.ledger(w.ana.human());
  const refusals = ledger.filter((e) => e.kind === "refused_outbound");
  assert.equal(refusals.length, drafts.length);
  for (const entry of refusals) {
    const payload = await w.example.ledgerPayload(w.ana.human(), entry.seq);
    assert.ok(payload?.detail?.length, "the payload keeps the reasons");
    texts.push(JSON.stringify(entry), JSON.stringify(payload));
  }
  for (const t of texts) for (const v of values) assert.ok(!t.includes(v), `${v} isn't echoed: ${t.slice(0, 300)}`);
});
