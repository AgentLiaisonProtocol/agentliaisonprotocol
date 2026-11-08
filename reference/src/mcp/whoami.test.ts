// SPDX-License-Identifier: FSL-1.1-ALv2
// alp_whoami's text about the person's own agents (spec 6.14): which of them can receive a message now, how to address
// them and what the agent may send them, which needs no relationship. Only the same person's agents are named, and the
// structured result stays as tools.json defines it.

import assert from "node:assert/strict";
import { test } from "node:test";
import { ANA, CLIENTS, LEE, MALLORY, buildWorld, examplePolicy } from "../demo/world.ts";
import type { DelegateCaller, OrgPolicy } from "../core/types.ts";
import { BindingState } from "../oauth/state.ts";
import type { AuthContext } from "../oauth/resource.ts";
import { runTool } from "./handlers.ts";
import type { ToolContext, ToolOutcome } from "./handlers.ts";
import { toolCatalog } from "./tools.ts";

function auth(caller: DelegateCaller, principalId: string): AuthContext {
  return { caller, principal_id: principalId, scopes: ["read", "send"], via: "oauth", resource: "mcp" };
}

function ok(o: ToolOutcome): Extract<ToolOutcome, { ok: true }> {
  assert.equal(o.ok, true, JSON.stringify(o));
  return o as Extract<ToolOutcome, { ok: true }>;
}

// What an open thread takes (spec 9.2), without the negotiation types one person's own agents never use: in the scopes
// that negotiate, an inform reports what happened after a commit, so it isn't among them.
const OWN_SCOPES = [
  "alp.availability/1 (start with request; continue with request, decline, inform, ask_human, ack, error)",
  "alp.briefing/1 (start with request; continue with request, decline, inform, ask_human, ack, error)",
  "alp.document_request/1 (start with request; continue with request, decline, ask_human, ack, error)",
  "alp.meeting/1 (start with request; continue with request, decline, ask_human, ack, error)",
  "alp.status/1 (start with request or inform; continue with request, decline, inform, ask_human, ack, error)",
];

test("spec 6.14: with no relationships, alp_whoami names the person's other agents, how to address them and what the agent may send them", async () => {
  // example.org without its default relationship: Lee has no relationship with anyone else.
  let policy: OrgPolicy = examplePolicy(new Date("2026-11-09T14:00:00Z"), { default_relationships: [] });
  const w = await buildWorld({ domainDocs: false, policy: () => policy });
  const lee = (await w.example.getPrincipal(LEE))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [policy], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const muse = await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  const planner = await w.example.registerDelegate({ principal: LEE, label: "planner", kind: "bridged", client_id: CLIENTS.consumer });
  const old = await w.example.registerDelegate({ principal: LEE, label: "old", kind: "bridged", client_id: CLIENTS.consumer });
  await w.example.revokeDelegate(old.id);
  const museCaller: DelegateCaller = { kind: "delegate", principal: LEE, delegate: muse.id, client_id: CLIENTS.consumer };
  const plannerCaller: DelegateCaller = { kind: "delegate", principal: LEE, delegate: planner.id, client_id: CLIENTS.consumer };
  const whoami = async (caller: DelegateCaller, args: Record<string, unknown> = {}) => ok(await runTool(ctx, auth(caller, lee.principal_id), "alp_whoami", args));

  // Lee's company agent (dot): its client may use every scope.
  const dot = await whoami(w.lee.agent);
  assert.equal(dot.text, [
    "You act for lee@example.org (Lee) as delegate alp:lee@example.org/dot, through the broker https://broker.example.org.",
    "Recorded for this agent: attestation vendor, class business.",
    "Your person has no relationships with other people yet: to reach someone else, use alp_request_connection.",
    "Your person's other agents: muse (consumer, self-attested), planner (consumer, self-attested).",
    "To write to one, use alp_send with to = lee@example.org (your person's own address) and to_delegate = its label; no connection is needed.",
    `Scopes you can use with them: ${OWN_SCOPES.join("; ")}.`,
    "Call again with include_scopes: true for the body schemas.",
  ].join(" "));
  assert.doesNotMatch(dot.text, /You have no relationships yet/, "never the wording that says the agent can't send anything");
  assert.doesNotMatch(dot.text, /\b(?:old|dot|claude) \(/, "neither a disconnected agent, nor the agent itself, nor another person's (Fran's claude)");
  assert.deepEqual(dot.structured["scopes"], [], "the structured scopes still list only what relationships allow");
  assert.deepEqual(toolCatalog().validateOutput("alp_whoami", dot.structured), []);

  // The personal agent (muse): the organization's list lets its client use two scopes, so it is told those two.
  const personal = await whoami(museCaller);
  assert.match(personal.text, /Your person's other agents: dot \(business, vendor-attested\), planner \(consumer, self-attested\)\./);
  assert.ok(personal.text.includes(`Scopes you can use with them: ${OWN_SCOPES.slice(0, 2).join("; ")}. Call again`), personal.text);

  // What the text says works: a status update to muse, which starts a thread.
  const sent = ok(await runTool(ctx, auth(w.lee.agent, lee.principal_id), "alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.status/1", type: "inform", body: { subject: "Board pack", state: "in_progress", updated_at: "2026-11-09T13:00:00Z" } }));
  assert.equal(sent.structured["status"], "delivered", sent.text);
  assert.match(sent.text, /^Delivered to your agent muse: alp\.status\/1 inform/);

  // include_scopes: the structured result is the same, and the text carries the body schemas for those agents.
  const withSchemas = await whoami(w.lee.agent, { include_scopes: true });
  assert.deepEqual(withSchemas.structured, dot.structured);
  const marker = "The body schemas for what you can send your person's other agents, by scope and type: ";
  assert.ok(withSchemas.text.includes(marker), withSchemas.text.slice(0, 2000));
  assert.doesNotMatch(withSchemas.text, /structuredContent\.scopes/, "nothing to find there: Lee has no relationships");
  const schemas = JSON.parse(withSchemas.text.slice(withSchemas.text.indexOf(marker) + marker.length)) as Record<string, Record<string, unknown>>;
  assert.deepEqual(Object.keys(schemas), ["alp.availability/1", "alp.briefing/1", "alp.document_request/1", "alp.meeting/1", "alp.status/1"]);
  assert.deepEqual(Object.keys(schemas["alp.status/1"] ?? {}), ["request", "decline", "inform", "ask_human", "ack", "error"]);
  assert.deepEqual(schemas["alp.status/1"]?.["inform"], w.scopes.require("alp.status/1").def.types.inform?.schema);

  // Only agents that can receive now, as the organization's current list ranks them: muse blocked, and the list now
  // ranking the connector client lower.
  const connector = (policy.clients?.allowed ?? []).find((r) => r.client_id === CLIENTS.connector);
  assert.ok(connector && policy.clients);
  policy = { ...policy, serial: 2, blocked: { delegates: [muse.id] }, clients: { ...policy.clients, allowed: [...policy.clients.allowed.filter((r) => r !== connector), { ...connector, attestation: "self", class: "consumer" }] } };
  await w.example.setOrgPolicy({ kind: "admin", operator: "it" }, policy);
  assert.match((await whoami(w.lee.agent)).text, /Your person's other agents: planner \(consumer, self-attested\)\. /);
  assert.match((await whoami(plannerCaller)).text, /Your person's other agents: dot \(consumer, self-attested\)\. /);
});

test("spec 6.14: with relationships and one other agent, alp_whoami keeps the relationship sentence and adds the agent", async () => {
  // example.org's list also names a notes client that may use no scope.
  const notesClient = "https://notes.example/client-metadata.json";
  const policy = (now: Date): OrgPolicy => {
    const p = examplePolicy(now);
    return { ...p, clients: { mode: "enforce", allowed: [...(p.clients?.allowed ?? []), { client_id: notesClient, scopes: [], attestation: "self", class: "consumer", no_training: false }] } };
  };
  const w = await buildWorld({ domainDocs: false, policy });
  const lee = (await w.example.getPrincipal(LEE))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [policy(w.clock.now())], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  const r = ok(await runTool(ctx, auth(w.lee.agent, lee.principal_id), "alp_whoami", {}));

  const scopes = r.structured["scopes"] as { id: string; types: string[] }[];
  assert.deepEqual(scopes.map((s) => s.id), ["alp.availability/1", "alp.briefing/1"], "the organization default, as before");
  assert.deepEqual(toolCatalog().validateOutput("alp_whoami", r.structured), []);
  const relationships = `Scopes you can use: ${scopes.map((s) => `${s.id} (${s.types.join(", ")})`).join("; ")}.`;
  assert.equal(r.text, [
    "You act for lee@example.org (Lee) as delegate alp:lee@example.org/dot, through the broker https://broker.example.org.",
    "Recorded for this agent: attestation vendor, class business.",
    relationships,
    "Your person's other agents: muse (consumer, self-attested).",
    "To write to one, use alp_send with to = lee@example.org (your person's own address) and to_delegate = its label; no connection is needed.",
    `Scopes you can use with them: ${OWN_SCOPES.join("; ")}.`,
    "Call again with include_scopes: true for the body schemas.",
  ].join(" "));

  // With include_scopes, the relationships' schemas stay in structuredContent and the text adds the own agents' ones.
  const withSchemas = ok(await runTool(ctx, auth(w.lee.agent, lee.principal_id), "alp_whoami", { include_scopes: true }));
  assert.match(withSchemas.text, /The body schema for each type is in structuredContent\.scopes\[\]\.schemas\. The body schemas for what you can send your person's other agents, by scope and type: \{"alp\.availability\/1":/);
  assert.ok((withSchemas.structured["scopes"] as Record<string, unknown>[]).every((s) => s["schemas"]), "structuredContent keeps its schemas");

  // An agent whose client may use no scope: Lee's relationships exist, so it isn't told he has none.
  const notes = await w.example.registerDelegate({ principal: LEE, label: "notes", kind: "bridged", client_id: notesClient });
  const n = ok(await runTool(ctx, auth({ kind: "delegate", principal: LEE, delegate: notes.id, client_id: notesClient }, lee.principal_id), "alp_whoami", {}));
  assert.deepEqual(n.structured["scopes"], []);
  assert.match(n.text, / Your person has relationships with other people, but this agent's client may use none of their scopes\. Your person's other agents: dot \(business, vendor-attested\), muse \(consumer, self-attested\)\. /);
  assert.match(n.text, / None of the scopes this agent may use lets it start a thread with them\. /);
  assert.doesNotMatch(n.text, /no relationships/);
});

test("spec 6.14: a person with no other agents is told there are none, and never shown another person's", async () => {
  // Ana's only agent, on a broker where Lee and Fran have theirs.
  const w = await buildWorld({ domainDocs: false });
  const ana = (await w.example.getPrincipal(ANA))!;
  await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [examplePolicy(w.clock.now())], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const r = ok(await runTool(ctx, auth(w.ana.agent, ana.principal_id), "alp_whoami", {}));
  assert.match(r.text, /^You act for ana@example\.org \(Ana\) as delegate alp:ana@example\.org\/muse, .* Scopes you can use: alp\.availability\/1 \([a-z_, ]+\); alp\.briefing\/1 \([a-z_, ]+\)\. Your person's other agents: none\. Call again with include_scopes: true for the body schemas\.$/);
  assert.doesNotMatch(r.text, /to_delegate|with them|\b(?:dot|claude) \(/, "nothing about Lee's or Fran's agents");

  // Mallory: no relationships and no other agents. The relationship wording stays: there is no one to write to.
  const mallory = (await w.outside.getPrincipal(MALLORY))!;
  const outside: ToolContext = { ...ctx, broker: w.outside, policies: () => [] };
  const m = ok(await runTool(outside, auth(w.mallory.agent, mallory.principal_id), "alp_whoami", {}));
  assert.equal(m.text, [
    "You act for mallory@outside.example (Mallory) as delegate alp:mallory@outside.example/agent, through the broker https://broker.outside.example.",
    "Recorded for this agent: attestation self, class consumer.",
    "You have no relationships yet: use alp_request_connection.",
    "Your person's other agents: none.",
    "Call again with include_scopes: true for the body schemas.",
  ].join(" "));
  assert.deepEqual(m.structured["scopes"], []);
});
