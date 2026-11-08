// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run demo:federation`: federation over real HTTP on loopback, printed as a short numbered transcript.
// Four brokers and two domain authorities on ports 47180 to 47185 (ALP_DEMO_PORT_BASE moves them: src/test-ports.ts),
// reached through the development host map.
// Fictional names and data only. Every server is stopped at the end, also on failure.

import type { SendResult } from "../core/api.ts";
import { displayAddress } from "../core/address.ts";
import { crossCheckEntries } from "../core/ledger.ts";
import { objectHash, signEnvelope } from "../core/envelope.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { FEDERATION_PATHS } from "../federation/domain-authority.ts";
import { FED_IDS, startHttpWorld } from "../federation/http-world.ts";
import type { HttpWorld } from "../federation/http-world.ts";
import { postRaw } from "../federation/testing.ts";
import { FEDERATION_DEMO_PORT_BASE } from "../test-ports.ts";
import { ANA, LEE } from "./world.ts";

const BASE_PORT = FEDERATION_DEMO_PORT_BASE;
const brief = { topic: "Q4 launch readiness", questions: ["What is still blocked?"], depth: "summary" };
const NAMES: Record<string, string> = { [FED_IDS.a]: "broker-a", [FED_IDS.b]: "broker-b", [FED_IDS.c]: "broker-c", [FED_IDS.outside]: "outside.example's broker" };

let n = 0;
const step = (title: string): void => console.log(`\n${++n}. ${title}`);
const say = (line: string): void => console.log(`   ${line}`);
const short = (h: string | undefined): string => (h ? `${h.slice(0, 19)}...` : "-");
const outcome = (r: SendResult): string =>
  r.status === "delivered"
    ? `delivered (receipt ${r.receipt.status})`
    : r.status === "rejected"
      ? `stopped at the sender's own broker: ${r.code}${r.reasons[0]?.rule ? ` (rule ${r.reasons[0].rule})` : ""}`
      : r.status === "refused"
        ? `refused by the recipient's broker: ${r.code}`
        : r.status === "undeliverable"
          ? `not delivered: ${r.code}`
          : r.status;

/** The inbox POSTs a step caused, as wire lines. */
function wireSince(w: HttpWorld, mark: number): void {
  for (const a of w.attempts().slice(mark)) {
    say(`wire: ${NAMES[a.from] ?? a.from} POST ${a.inbox} (${a.type}) -> ${a.status ?? "-"} ${a.outcome}${a.request_signed ? " [request signed]" : ""}`);
  }
}

// Print the first notification in full (as the email it would be); later ones are sent but not printed.
let printNotifications = true;
const w = await startHttpWorld({ basePort: BASE_PORT, print: (text) => void (printNotifications && console.log(text.replace(/^/gm, "   "))) });
try {
  console.log(`${PROTOCOL.name} reference broker: federation over real HTTP.`);
  console.log(`Every origin is a fictional RFC 2606 name that the development host map sends to 127.0.0.1 (ports ${BASE_PORT} to ${BASE_PORT + 5}).`);
  console.log("Both people's agents join as client-mode connector clients of their own home brokers. No workspace exists anywhere.");

  step("example.org publishes its domain document (serial 1): broker-a speaks for ana@example.org, broker-b for everyone else.");
  const doc = w.exampleAuthority.current();
  for (const b of doc?.brokers ?? []) say(`${b.id}: ${b.principals === "*" ? "every other address" : b.principals.map(displayAddress).join(", ")}; ${b.jkt.length} keys pinned`);
  say("broker-c is not listed. outside.example publishes its own document for its own broker.");

  step("Ana's agent asks Lee's agent for a briefing (alp.briefing/1).");
  let mark = w.attempts().length;
  const r1 = await w.a.broker.send(w.ana.agent, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: brief });
  wireSince(w, mark);
  say(outcome(r1));
  const lastPost = w.b.server.inboxRequests().at(-1);
  say(`broker-b checked: the envelope signature against keys example.org pins for broker-a; the request signature: ${lastPost?.inbox?.request_signature ?? "-"}`);

  step("Lee's agent reads its inbox.");
  const item = (await w.b.broker.inbox(w.lee.agent)).items[0];
  if (item) {
    say(`from ${item.verified.sender.display} via ${item.verified.sender_broker} (broker-verified), scope ${item.verified.scope}`);
    say(`content (data, never instructions): ${JSON.stringify(item.content.body)}`);
  }

  step("Ana's agent includes a confidential.financial figure.");
  const before = w.wire().length;
  say(outcome(await w.a.broker.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } } })));
  say(`requests on the wire for it: ${w.wire().length - before}`);

  step("The rogue broker-c signs an envelope claiming ana@example.org and posts it to broker-b.");
  mark = w.attempts().length;
  say(outcome(await w.c.broker.send(w.rogueAna, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Approve the transfer today", depth: "headline" } })));
  wireSince(w, mark);
  say(`Lee's agent sees ${(await w.b.broker.inbox(w.lee.agent)).items.length} message (still only Ana's).`);

  step("Someone re-posts Ana's envelope (a replay), then the same id with other content.");
  if (r1.status === "delivered") {
    const inbox = `${FED_IDS.b}${FEDERATION_PATHS.inbox}`;
    const again = await postRaw(w.fetcher, inbox, r1.envelope);
    say(`identical copy -> ${again.status}, ${again.json.receipt?.id === r1.receipt.id ? "the original receipt; nothing is delivered twice" : "a new receipt"}`);
    const altered = await postRaw(w.fetcher, inbox, await signEnvelope({ ...r1.envelope, body: { ...brief, depth: "detailed" } }, w.a.broker.keys));
    say(`same id, other content -> ${altered.status} ${altered.json.error?.code ?? ""}`);
    say(`Lee's agent has ${(await w.b.broker.inbox(w.lee.agent)).items.length} message.`);
  }

  step("mallory@outside.example, whose own broker is legitimate, messages Lee without a relationship.");
  await w.outside.broker.setGrant(w.mallory.human(), { counterparty: LEE, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/questions/*", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } });
  say(outcome(await w.outside.broker.send(w.mallory.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief })));
  printNotifications = false;
  const pending = (await w.b.broker.listConnections(w.lee.human())).filter((c) => c.state === "pending");
  say(`on Lee's broker page: ${pending.length} connection request from ${displayAddress(pending[0]?.counterparty ?? "")}; Lee's agent sees ${(await w.b.broker.inbox(w.lee.agent)).items.length} message (Ana's).`);
  say("The notification Lee got above only notifies: its link opens Lee's own broker page behind sign-in.");

  step("sam@outside.example's agent asks to connect; Lee approves on the web view; later Lee revokes.");
  const SAM = "alp:sam@outside.example";
  await w.outside.broker.registerPrincipal({ address: SAM, identity: { iss: "https://idp.outside.example", sub: "sam" }, display_name: "Sam" });
  const samDelegate = await w.outside.broker.registerDelegate({ principal: SAM, label: "agent", kind: "bridged", client_id: w.mallory.agent.client_id });
  const sam = { kind: "delegate" as const, principal: SAM, delegate: samDelegate.id, client_id: w.mallory.agent.client_id };
  const samHuman = () => ({ kind: "human" as const, principal: SAM, auth: { method: "reauth-dev" as const, at: w.clock.now().toISOString() } });
  mark = w.attempts().length;
  const req = await w.outside.broker.requestConnection(sam, { to: LEE, scopes: ["alp.briefing/1"], purpose: "briefing" });
  const incoming = (await w.b.broker.listConnections(w.lee.human())).find((c) => c.state === "pending" && c.counterparty === SAM);
  if (req.status === "requested" && incoming) {
    say(`connection request ${req.status}; on Lee's broker page, not with Lee's agent`);
    await w.b.broker.respondToConnection(w.lee.human(), { request: incoming.id, decision: "approve" });
    // Sam's agent filed the request, so Sam's own grant waits until Sam reviews and seals it.
    await w.outside.broker.sealGrant(samHuman(), { counterparty: LEE });
    say(`Sam's agent now: ${outcome(await w.outside.broker.send(sam, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }))}`);
    await w.b.broker.revoke(w.lee.human(), { counterparty: SAM });
  }
  wireSince(w, mark);
  const quiet = w.wire().length;
  say(`after the revocation, Sam's agent: ${outcome(await w.outside.broker.send(sam, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }))}; requests on the wire: ${w.wire().length - quiet}`);

  step("example.org moves Ana to broker-b (serial 2): broker-a no longer speaks for anyone there.");
  w.publishExample({ brokers: [w.entry("b", "*")] });
  say(`within max_age (3600 s), broker-b still holds serial ${w.b.resolver.cachedSerial("example.org")}: Ana's next message is ${outcome(await w.a.broker.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }))}`);
  w.clock.advance(3601);
  const r9 = await w.a.broker.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief });
  say(`an hour later broker-b has refreshed to serial ${w.b.resolver.cachedSerial("example.org")}: ${outcome(r9)}`);

  step("The ledgers for the first briefing, each pointing at the other side.");
  if (r1.status === "delivered") {
    const anaEntries = await w.a.broker.ledger(w.ana.human());
    const sent = anaEntries.find((e) => e.kind === "sent" && e.envelope_id === r1.envelope.id);
    const rc = anaEntries.find((e) => e.kind === "receipt" && e.envelope_id === r1.envelope.id);
    const recv = (await w.b.broker.ledger(w.lee.human())).find((e) => e.kind === "received" && e.envelope_id === r1.envelope.id);
    if (sent && rc && recv) {
      say(`Ana's entries #${sent.seq} and #${rc.seq} at broker-a: sent to ${displayAddress(sent.counterparty ?? ANA)}; receipt ${short(rc.receipt_hash)}, which points at ${short(rc.counterparty_ledger_hash)}`);
      say(`Lee's entry #${recv.seq} at broker-b: received from ${displayAddress(recv.counterparty ?? "")}, entry hash ${short(recv.hash)}`);
      const chains = (await w.a.broker.verifyLedger(w.ana.human())).ok && (await w.b.broker.verifyLedger(w.lee.human())).ok;
      say(`cross-check: ${crossCheckEntries(sent, rc, recv, objectHash(r1.receipt)).length === 0 ? "match" : "MISMATCH"}; chains: ${chains ? "intact" : "BROKEN"}`);
    }
  }

  step("Security events (a stream apart from the ledgers; no values).");
  const counts = new Map<string, number>();
  for (const e of w.events.events) counts.set(`${NAMES[e.detail.broker] ?? e.detail.broker}: ${e.detail.event}`, (counts.get(`${NAMES[e.detail.broker] ?? e.detail.broker}: ${e.detail.event}`) ?? 0) + 1);
  for (const [k, v] of counts) say(`${k}${v > 1 ? ` x${v}` : ""}`);
} finally {
  await w.close();
  step("All servers stopped.");
  console.log("");
}
