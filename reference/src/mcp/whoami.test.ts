// SPDX-License-Identifier: FSL-1.1-ALv2
// alp_whoami and the person's own agents (spec 6.14). The structured `scopes`, which the REST mirror returns, lists every
// scope the agent can use: what the person's relationships allow and what it may send the person's other agents, which
// needs no relationship, merged per scope, within the scopes the organization's list gives its client when the list is
// enforced. The text keeps the two apart: it names the other agents that can receive a message now, how to address them
// and what the agent may send them. Only the same person's agents count, and every result matches tools.json's output
// schema, in process and over HTTP, where the MCP endpoint's structuredContent is the REST mirror's body.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { ANA, CLIENTS, LEE, MALLORY, buildWorld, examplePolicy } from "../demo/world.ts";
import type { DelegateCaller, OrgPolicy } from "../core/types.ts";
import { mintPat } from "../oauth/pat.ts";
import { BindingState } from "../oauth/state.ts";
import type { AuthContext } from "../oauth/resource.ts";
import { runTool } from "./handlers.ts";
import type { ToolContext, ToolOutcome } from "./handlers.ts";
import { startTestBroker } from "./testkit.ts";
import type { TestBroker } from "./testkit.ts";
import { toolCatalog } from "./tools.ts";

type Listed = { id: string; title: string; types: string[]; schemas?: Record<string, unknown> };

function auth(caller: DelegateCaller, principalId: string): AuthContext {
  return { caller, principal_id: principalId, scopes: ["read", "send"], via: "oauth", resource: "mcp" };
}

function ok(o: ToolOutcome): Extract<ToolOutcome, { ok: true }> {
  assert.equal(o.ok, true, JSON.stringify(o));
  return o as Extract<ToolOutcome, { ok: true }>;
}

/** alp_whoami through the tool handler both mirrors share; its structured result must match tools.json. */
async function whoamiAs(ctx: ToolContext, caller: DelegateCaller, principalId: string, args: Record<string, unknown> = {}): Promise<Extract<ToolOutcome, { ok: true }>> {
  const r = ok(await runTool(ctx, auth(caller, principalId), "alp_whoami", args));
  assert.deepEqual(toolCatalog().validateOutput("alp_whoami", r.structured), [], "the structured result matches tools.json's output schema");
  return r;
}

const listedOf = (structured: Record<string, unknown>): Listed[] => structured["scopes"] as Listed[];
/** Each listed scope with its types, in the order listed. */
const scopeTypes = (structured: Record<string, unknown>): [string, string[]][] => listedOf(structured).map((s) => [s.id, s.types]);

// What an open thread takes (spec 9.2), without the negotiation types one person's own agents never use: in the scopes
// that negotiate, an inform reports what happened after a commit, so it isn't among them.
const OWN_SCOPES = [
  "alp.availability/1 (start with request; continue with request, decline, inform, ask_human, ack, error)",
  "alp.briefing/1 (start with request; continue with request, decline, inform, ask_human, ack, error)",
  "alp.document_request/1 (start with request; continue with request, decline, ask_human, ack, error)",
  "alp.meeting/1 (start with request; continue with request, decline, ask_human, ack, error)",
  "alp.status/1 (start with request or inform; continue with request, decline, inform, ask_human, ack, error)",
];
// The same types as the structured result lists them: those that start or continue a thread, in the protocol's order.
const OWN_TYPES: [string, string[]][] = [
  ["alp.availability/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
  ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
  ["alp.document_request/1", ["request", "decline", "ask_human", "ack", "error"]],
  ["alp.meeting/1", ["request", "decline", "ask_human", "ack", "error"]],
  ["alp.status/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
];

test("spec 6.14: with no relationships, alp_whoami lists the scopes the agent can use with the person's other agents, names them and says how to address them", async () => {
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
  const whoami = (caller: DelegateCaller, args: Record<string, unknown> = {}) => whoamiAs(ctx, caller, lee.principal_id, args);

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
  // The structured result lists the same scopes, so an agent that reads only it (a REST client) can write to them too.
  assert.deepEqual(scopeTypes(dot.structured), OWN_TYPES);
  assert.deepEqual(listedOf(dot.structured)[4], { id: "alp.status/1", title: "Status", types: ["request", "decline", "inform", "ask_human", "ack", "error"] }, "no schemas without include_scopes");

  // The personal agent (muse): the organization's list lets its client use two scopes, so it is told those two.
  const personal = await whoami(museCaller);
  assert.match(personal.text, /Your person's other agents: dot \(business, vendor-attested\), planner \(consumer, self-attested\)\./);
  assert.ok(personal.text.includes(`Scopes you can use with them: ${OWN_SCOPES.slice(0, 2).join("; ")}. Call again`), personal.text);
  assert.deepEqual(scopeTypes(personal.structured), OWN_TYPES.slice(0, 2), "and so is the structured result");

  // What the result says works: a status update to muse, which starts a thread.
  const sent = ok(await runTool(ctx, auth(w.lee.agent, lee.principal_id), "alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.status/1", type: "inform", body: { subject: "Board pack", state: "in_progress", updated_at: "2026-11-09T13:00:00Z" } }));
  assert.equal(sent.structured["status"], "delivered", sent.text);
  assert.match(sent.text, /^Delivered to your agent muse: alp\.status\/1 inform/);

  // include_scopes: each listed type's body schema is in the structured result, and the text still carries them.
  const withSchemas = await whoami(w.lee.agent, { include_scopes: true });
  assert.deepEqual(listedOf(withSchemas.structured).map(({ id, title, types }) => ({ id, title, types })), listedOf(dot.structured), "the same scopes and types");
  const marker = "The body schemas for what you can send your person's other agents, by scope and type: ";
  assert.ok(withSchemas.text.includes(`The body schema for each type is in structuredContent.scopes[].schemas. ${marker}`), withSchemas.text.slice(0, 2000));
  const schemas = JSON.parse(withSchemas.text.slice(withSchemas.text.indexOf(marker) + marker.length)) as Record<string, Record<string, unknown>>;
  assert.deepEqual(Object.keys(schemas), ["alp.availability/1", "alp.briefing/1", "alp.document_request/1", "alp.meeting/1", "alp.status/1"]);
  assert.deepEqual(Object.keys(schemas["alp.status/1"] ?? {}), ["request", "decline", "inform", "ask_human", "ack", "error"]);
  assert.deepEqual(schemas["alp.status/1"]?.["inform"], w.scopes.require("alp.status/1").def.types.inform?.schema);
  for (const s of listedOf(withSchemas.structured)) assert.deepEqual(s.schemas, schemas[s.id], `${s.id}: the text's schemas are the structured result's`);

  // Only agents that can receive now, as the organization's current list ranks them: muse blocked, and the list now
  // ranking the connector client lower.
  const connector = (policy.clients?.allowed ?? []).find((r) => r.client_id === CLIENTS.connector);
  assert.ok(connector && policy.clients);
  policy = { ...policy, serial: 2, blocked: { delegates: [muse.id] }, clients: { ...policy.clients, allowed: [...policy.clients.allowed.filter((r) => r !== connector), { ...connector, attestation: "self", class: "consumer" }] } };
  await w.example.setOrgPolicy({ kind: "admin", operator: "it" }, policy);
  assert.match((await whoami(w.lee.agent)).text, /Your person's other agents: planner \(consumer, self-attested\)\. /);
  assert.match((await whoami(plannerCaller)).text, /Your person's other agents: dot \(consumer, self-attested\)\. /);

  // With no other agent that can receive a message (muse blocked, planner disconnected, and one whose client the
  // organization's list doesn't name), nothing is listed.
  await w.example.revokeDelegate(planner.id);
  await w.example.registerDelegate({ principal: LEE, label: "unlisted", kind: "bridged", client_id: CLIENTS.unlisted });
  const alone = await whoami(w.lee.agent);
  assert.deepEqual(alone.structured["scopes"], []);
  assert.match(alone.text, / You have no relationships yet: use alp_request_connection\. Your person's other agents: none\. /);
});

test("spec 6.14: with relationships and another agent, alp_whoami's scopes merge both kinds per scope, and the text keeps them apart", async () => {
  // example.org's list also names a notes client that may use no scope, and its staff default also lets Lee's agent ask
  // for, propose, accept and commit meetings: one person's own agents never propose, accept or commit to each other.
  const notesClient = "https://notes.example/client-metadata.json";
  const policy = (now: Date): OrgPolicy => {
    const p = examplePolicy(now);
    const [staff] = p.default_relationships ?? [];
    assert.ok(staff);
    return {
      ...p,
      default_relationships: [{ ...staff, scopes: { ...staff.scopes, "alp.meeting/1": { forward: { may: ["request", "propose", "counter", "accept", "commit"], fields: ["/body/title", "/body/window", "/body/duration_minutes", "/body/slots", "/body/terms"] } } } }],
      clients: { mode: "enforce", allowed: [...(p.clients?.allowed ?? []), { client_id: notesClient, scopes: [], attestation: "self", class: "consumer", no_training: false }] },
    };
  };
  const w = await buildWorld({ domainDocs: false, policy });
  const lee = (await w.example.getPrincipal(LEE))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [policy(w.clock.now())], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const muse = await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  const r = await whoamiAs(ctx, w.lee.agent, lee.principal_id);

  // What Lee's relationships allow (the staff default, with Ana and Fran), and what dot may send muse, merged per scope.
  const withPeople: [string, string[]][] = [
    ["alp.availability/1", ["request", "decline", "inform", "ack", "error"]],
    ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
    ["alp.meeting/1", ["request", "propose", "counter", "accept", "decline", "commit", "ack", "error"]],
  ];
  assert.deepEqual(scopeTypes(r.structured), [
    // ask_human goes only to his own agents here; the default doesn't list it.
    ["alp.availability/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
    ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
    // Only with his own agents.
    ["alp.document_request/1", ["request", "decline", "ask_human", "ack", "error"]],
    // propose, counter, accept and commit only with other people; ask_human only with his own agents.
    ["alp.meeting/1", ["request", "propose", "counter", "accept", "decline", "ask_human", "commit", "ack", "error"]],
    ["alp.status/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
  ]);
  assert.equal(r.text, [
    "You act for lee@example.org (Lee) as delegate alp:lee@example.org/dot, through the broker https://broker.example.org.",
    "Recorded for this agent: attestation vendor, class business.",
    `Scopes you can use with other people: ${withPeople.map(([id, types]) => `${id} (${types.join(", ")})`).join("; ")}.`,
    "Your person's other agents: muse (consumer, self-attested).",
    "To write to one, use alp_send with to = lee@example.org (your person's own address) and to_delegate = its label; no connection is needed.",
    `Scopes you can use with them: ${OWN_SCOPES.join("; ")}.`,
    "Call again with include_scopes: true for the body schemas.",
  ].join(" "));

  // With include_scopes, every listed type has its body schema in the structured result, one only relationships allow
  // included; the text points there and still carries the own agents' schemas.
  const withSchemas = await whoamiAs(ctx, w.lee.agent, lee.principal_id, { include_scopes: true });
  assert.match(withSchemas.text, /The body schema for each type is in structuredContent\.scopes\[\]\.schemas\. The body schemas for what you can send your person's other agents, by scope and type: \{"alp\.availability\/1":/);
  for (const s of listedOf(withSchemas.structured)) assert.deepEqual(Object.keys(s.schemas ?? {}), s.types, `${s.id}: a schema for each type`);
  const meeting = listedOf(withSchemas.structured).find((s) => s.id === "alp.meeting/1");
  assert.deepEqual(meeting?.schemas?.["propose"], w.scopes.require("alp.meeting/1").def.types.propose?.schema);

  // The organization's list lets muse's client use two scopes: the meeting relationship and the scopes only Lee's own
  // agents give are left out of both.
  const m = await whoamiAs(ctx, { kind: "delegate", principal: LEE, delegate: muse.id, client_id: CLIENTS.consumer }, lee.principal_id);
  assert.deepEqual(scopeTypes(m.structured), scopeTypes(r.structured).slice(0, 2));
  assert.match(m.text, /Scopes you can use with other people: alp\.availability\/1 \(request, decline, inform, ack, error\); alp\.briefing\/1 \(request, decline, inform, ask_human, ack, error\)\. Your person's other agents: dot \(business, vendor-attested\)\. /);

  // An agent whose client may use no scope: Lee's relationships exist, so it isn't told he has none, and nothing is listed.
  const notes = await w.example.registerDelegate({ principal: LEE, label: "notes", kind: "bridged", client_id: notesClient });
  const n = await whoamiAs(ctx, { kind: "delegate", principal: LEE, delegate: notes.id, client_id: notesClient }, lee.principal_id);
  assert.deepEqual(n.structured["scopes"], []);
  assert.match(n.text, / Your person has relationships with other people, but this agent's client may use none of their scopes\. Your person's other agents: dot \(business, vendor-attested\), muse \(consumer, self-attested\)\. /);
  assert.match(n.text, / None of the scopes this agent may use lets it start a thread with them\. /);
  assert.doesNotMatch(n.text, /no relationships/);
});

test("spec 6.14: a person with no other agents is told there are none, never shown another person's, and gets only what relationships allow", async () => {
  // Ana's only agent, on a broker where Lee and Fran have theirs.
  const w = await buildWorld({ domainDocs: false });
  const ana = (await w.example.getPrincipal(ANA))!;
  await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [examplePolicy(w.clock.now())], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const r = await whoamiAs(ctx, w.ana.agent, ana.principal_id);
  assert.match(r.text, /^You act for ana@example\.org \(Ana\) as delegate alp:ana@example\.org\/muse, .* Scopes you can use: alp\.availability\/1 \(request, decline, inform, ack, error\); alp\.briefing\/1 \(request, decline, inform, ask_human, ack, error\)\. Your person's other agents: none\. Call again with include_scopes: true for the body schemas\.$/);
  assert.doesNotMatch(r.text, /to_delegate|with them|with other people|\b(?:dot|claude) \(/, "nothing about Lee's or Fran's agents");
  assert.deepEqual(scopeTypes(r.structured), [
    ["alp.availability/1", ["request", "decline", "inform", "ack", "error"]],
    ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
  ], "what the default allows, as before: nothing from Lee's agents");

  // Mallory: no relationships and no other agents. The relationship wording stays: there is no one to write to.
  const mallory = (await w.outside.getPrincipal(MALLORY))!;
  const outside: ToolContext = { ...ctx, broker: w.outside, policies: () => [] };
  const m = await whoamiAs(outside, w.mallory.agent, mallory.principal_id);
  assert.equal(m.text, [
    "You act for mallory@outside.example (Mallory) as delegate alp:mallory@outside.example/agent, through the broker https://broker.outside.example.",
    "Recorded for this agent: attestation self, class consumer.",
    "You have no relationships yet: use alp_request_connection.",
    "Your person's other agents: none.",
    "Call again with include_scopes: true for the body schemas.",
  ].join(" "));
  assert.deepEqual(m.structured["scopes"], []);
});

test("spec 6.14: past the 64 scopes tools.json allows, alp_whoami keeps what relationships allow before what only the person's other agents add", async () => {
  // 60 organization scopes besides the five core ones, and no organization's list, so Lee's agent may send his other
  // agents in all 65; his staff default also gives the last of them, which sorts after the rest.
  const last = "org.example.org.s59/1";
  const policy = (now: Date): OrgPolicy => {
    const p = examplePolicy(now, { clients: undefined });
    const [staff] = p.default_relationships ?? [];
    assert.ok(staff);
    return { ...p, default_relationships: [{ ...staff, scopes: { ...staff.scopes, [last]: { forward: { may: ["request"], fields: ["/body/subject"] } } } }] };
  };
  const w = await buildWorld({ domainDocs: false, policy });
  const status = w.scopes.require("alp.status/1").def;
  for (let i = 0; i < 60; i++) w.scopes.register({ ...structuredClone(status), id: `org.example.org.s${String(i).padStart(2, "0")}/1`, title: `Scope ${i}` });
  const lee = (await w.example.getPrincipal(LEE))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [policy(w.clock.now())], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const listed = async (): Promise<string[]> => listedOf((await whoamiAs(ctx, w.lee.agent, lee.principal_id)).structured).map((s) => s.id);

  assert.deepEqual(await listed(), ["alp.availability/1", "alp.briefing/1", last], "with no other agent, what relationships allow");
  // With another agent all 65 are usable: the one left out is the last of those only his other agents add, never one
  // his relationships allow.
  await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: CLIENTS.consumer });
  assert.deepEqual(await listed(), w.scopes.ids().filter((id) => id !== "org.example.org.s58/1"));
});

describe("alp_whoami over HTTP: the REST mirror's body is the MCP endpoint's structuredContent (spec 12.1.9)", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker();
  });
  after(async () => {
    await t?.close();
  });

  /** A personal access token for a new agent of the person (the development broker's list, in report mode, names pat). */
  async function newAgent(address: string, label: string): Promise<string> {
    const principal = await t.dev.broker.store.getPrincipal(address);
    assert.ok(principal);
    return (await mintPat({ broker: t.dev.broker, state: t.server.state, principal, label, scopes: ["read", "send"], days: 1, maxDays: 30, now: new Date() })).token;
  }

  /** A token for Ana's agent script, with her other agent helper (a token for an agent already connected keeps it). */
  async function anaWithHelper(): Promise<string> {
    const script = await newAgent(ANA, "script");
    await newAgent(ANA, "helper");
    return script;
  }

  /** alp_whoami with the token on the REST mirror and on the MCP endpoint: one structured result, matching tools.json. */
  async function whoami(token: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const res = await fetch(`${t.base}/rest/alp_whoami`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(args) });
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.deepEqual(toolCatalog().validateOutput("alp_whoami", body), [], "the REST body matches tools.json's output schema");
    const client = new Client({ name: "whoami", version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: { token: async () => token } }));
    try {
      const r = (await client.callTool({ name: "alp_whoami", arguments: args })) as CallToolResult;
      assert.deepEqual(r.structuredContent, body, "the MCP endpoint's structuredContent is the REST body");
    } finally {
      await client.close();
    }
    return body;
  }

  /** Changes the development broker's policy, as a reload of its file would. */
  async function install(change: (p: OrgPolicy) => void): Promise<void> {
    const current = t.dev.policies[0];
    assert.ok(current);
    const next = structuredClone(current);
    next.serial = current.serial + 1;
    change(next);
    await t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, next);
    t.dev.policies[0] = next;
  }

  test("no relationships but another agent: the scopes the agent may use with it, and their body schemas only with include_scopes", async () => {
    // Mallory, at outside.example: no relationship with anyone, and no organization's list.
    const script = await newAgent(MALLORY, "script");
    assert.deepEqual((await whoami(script))["scopes"], [], "her only agent has nothing to use yet");
    await newAgent(MALLORY, "helper");
    const plain = await whoami(script);
    assert.deepEqual(scopeTypes(plain), OWN_TYPES);
    assert.ok(listedOf(plain).every((s) => s.schemas === undefined), "no schemas without include_scopes");
    const full = await whoami(script, { include_scopes: true });
    assert.deepEqual(scopeTypes(full), OWN_TYPES);
    for (const s of listedOf(full)) assert.deepEqual(Object.keys(s.schemas ?? {}), s.types, `${s.id}: a schema for each type`);
    const status = listedOf(full).find((s) => s.id === "alp.status/1");
    assert.deepEqual(status?.schemas?.["inform"], t.dev.broker.scopes.require("alp.status/1").def.types.inform?.schema);

    // A send built from those fields goes through.
    const res = await fetch(`${t.base}/rest/alp_send`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${script}` }, body: JSON.stringify({ to: "mallory@outside.example", to_delegate: "helper", scope: "alp.status/1", type: "inform", body: { subject: "Board pack", state: "in_progress", updated_at: "2026-11-09T13:00:00Z" } }) });
    const sent = (await res.json()) as Record<string, unknown>;
    assert.equal(res.status, 200, JSON.stringify(sent));
    assert.equal(sent["status"], "delivered");
  });

  test("relationships and another agent: merged per scope; no other agent: only what relationships allow, as before", async () => {
    // Lee has one agent: what example.org's staff default allows.
    assert.deepEqual(scopeTypes(await whoami(await newAgent(LEE, "script"))), [
      ["alp.availability/1", ["request", "decline", "inform", "ack", "error"]],
      ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
      ["alp.status/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
    ]);
    // Ana has two: the default's types and what she may send her other agent, per scope.
    assert.deepEqual(scopeTypes(await whoami(await anaWithHelper())), [
      ["alp.availability/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
      ["alp.briefing/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
      ["alp.document_request/1", ["request", "decline", "ask_human", "ack", "error"]],
      ["alp.meeting/1", ["request", "decline", "ask_human", "ack", "error"]],
      ["alp.status/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
    ]);
  });

  test("the organization's list limits both kinds: a scope the client may not use is left out, whoever it would go to", async () => {
    const ana = await anaWithHelper();
    await install((p) => {
      p.clients = { mode: "enforce", allowed: [...(p.clients?.allowed ?? []).filter((c) => c.client_id !== "pat"), { client_id: "pat", scopes: ["alp.availability/1", "alp.document_request/1"], attestation: "self", class: "consumer", no_training: false }] };
    });
    try {
      // Briefing and status, which the default allows, and meeting, which only her other agent could be sent, are left out.
      assert.deepEqual(scopeTypes(await whoami(ana)), [
        ["alp.availability/1", ["request", "decline", "inform", "ask_human", "ack", "error"]],
        ["alp.document_request/1", ["request", "decline", "ask_human", "ack", "error"]],
      ]);
    } finally {
      await install((p) => {
        p.clients = { mode: "report", allowed: [...(p.clients?.allowed ?? []).filter((c) => c.client_id !== "pat"), { client_id: "pat", scopes: ["alp.availability/1", "alp.briefing/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"], attestation: "self", class: "consumer", no_training: false }] };
      });
    }
  });
});
