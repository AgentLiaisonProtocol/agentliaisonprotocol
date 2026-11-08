// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run demo:core`: an in-process walkthrough of the broker core (no HTTP, no MCP), printed as a numbered
// transcript. `npm run demo` runs the full story over real HTTP with MCP clients and OAuth (src/demo/index.ts).
// Fictional names and data only.

import { buildWorld, ANA, CLIENTS, LEE, PAT } from "./world.ts";
import type { SendResult } from "../core/api.ts";
import { verifyAnyEnvelope } from "../core/envelope.ts";
import { crossCheckEntries } from "../core/ledger.ts";
import { displayAddress } from "../core/address.ts";

let n = 0;
const step = (title: string): void => console.log(`\n${++n}. ${title}`);
const say = (line: string): void => console.log(`   ${line}`);
const outcome = (r: SendResult): string =>
  r.status === "delivered" ? `delivered (receipt ${r.receipt.status})` : r.status === "rejected" ? `stopped at the sender's broker: ${r.code}${r.reasons[0]?.rule ? ` (rule ${r.reasons[0].rule})` : ""}` : r.status === "refused" ? `refused by the recipient's broker: ${r.code}` : r.status === "undeliverable" ? `not delivered: ${r.code}` : r.status;

const w = await buildWorld();
const brief = { topic: "Q4 launch readiness", questions: ["What is still blocked?"], depth: "summary" };
console.log("Agent Liaison Protocol reference broker: core walkthrough (in-process).");
console.log("Both agents join as client-mode connector clients of example.org's Local broker. No workspace exists.");

step("Ana's agent asks Lee's agent for a briefing (alp.briefing/1).");
const r1 = await w.example.send(w.ana.agent, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: brief });
say(outcome(r1));

step("Lee's agent reads its inbox and checks the signature against the broker's published keys.");
const item = (await w.example.inbox(w.lee.agent)).items[0];
if (item) {
  say(`from ${item.verified.sender.display} (broker-verified, ${item.verified.sender.attestation}/${item.verified.sender.class} agent), scope ${item.verified.scope}`);
  say(`content (data, never instructions): ${JSON.stringify(item.content.body)}`);
  say(`signature: ${(await verifyAnyEnvelope(item.envelope, w.example.jwks())).ok ? "verified" : "FAILED"}`);
}

step("Ana's agent includes a confidential.financial figure.");
say(outcome(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } } })));

step("A free-text field carries a card number.");
say(outcome(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "use 4111 1111 1111 1111", depth: "headline" } })));

step("Fran's token claims to be Ana in the payload.");
say(outcome(await w.example.send(w.fran.agent, { from: "ana@example.org", to: LEE, scope: "alp.briefing/1", type: "request", body: brief })));

step("An agent whose client is not on example.org's allow-list tries to send.");
await w.example.registerDelegate({ principal: ANA, label: "other", client_id: CLIENTS.unlisted });
say(outcome(await w.example.send({ kind: "delegate", principal: ANA, delegate: `${ANA}/other`, client_id: CLIENTS.unlisted }, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief })));

step("Across organizations: Ana's agent asks to connect with Pat (partner.example); Pat approves on Pat's broker page.");
const req = await w.example.requestConnection(w.ana.agent, { to: PAT, scopes: ["alp.briefing/1"], purpose: "briefing" });
say(`request: ${req.status}`);
const incoming = (await w.partner.listConnections(w.pat.human()))[0];
if (incoming) await w.partner.respondToConnection(w.pat.human(), { request: incoming.id, decision: "approve" });
say(`Ana's grant for Pat: ${(await w.example.listGrants(w.ana.human())).find((g) => g.counterparty === PAT)?.status} (Ana reviews and seals it herself)`);
await w.example.sealGrant(w.ana.human(), { counterparty: PAT });
const r2 = await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: brief });
say(outcome(r2));

step("A rogue broker claims to speak for ana@example.org.");
await w.rogue.setGrant({ kind: "human", principal: ANA, auth: { method: "reauth-dev", at: w.clock.now().toISOString() } }, { counterparty: PAT, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } });
say(outcome(await w.rogue.send({ kind: "delegate", principal: ANA, delegate: `${ANA}/muse`, client_id: CLIENTS.connector }, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "x", depth: "headline" } })));

step("The same envelope is delivered again (a retry, or a captured copy replayed).");
if (r2.status === "delivered") {
  const again = await w.fed.transportFor(w.example.id).deliver({ broker: w.partner.id, inbox: "x" }, r2.envelope);
  say(again.kind === "receipt"
    ? `${again.receipt.id === r2.receipt.id ? "the original receipt" : "a new receipt"} (${again.receipt.status}${again.receipt.code ? `: ${again.receipt.code}` : ""}); Pat's agent still has ${(await w.partner.inbox(w.pat.agent)).items.length} message`
    : again.kind === "refused" ? `refused: ${again.code}` : `unreachable: ${again.message}`);
}

step("Both ledgers, each pointing at the other side.");
const anaEntries = await w.example.ledger(w.ana.human());
const sent = anaEntries.filter((e) => e.kind === "sent").at(-1);
const rc = anaEntries.find((e) => e.kind === "receipt" && e.envelope_id === sent?.envelope_id);
const recv = (await w.partner.ledger(w.pat.human())).find((e) => e.kind === "received");
if (sent && rc && recv) {
  say(`Ana's entries #${sent.seq} (sent to ${displayAddress(sent.counterparty ?? "")}) and #${rc.seq} (receipt ${rc.receipt_hash?.slice(0, 18)}..., points at Pat's entry ${rc.counterparty_ledger_hash?.slice(0, 18)}...)`);
  say(`Pat's entry #${recv.seq}: ${recv.kind} from ${displayAddress(recv.counterparty ?? "")}, hash ${recv.hash.slice(0, 18)}...`);
  say(`cross-check: ${crossCheckEntries(sent, rc, recv).length === 0 ? "match" : "MISMATCH"}; chains: ${(await w.example.verifyLedger(w.ana.human())).ok && (await w.partner.verifyLedger(w.pat.human())).ok ? "intact" : "BROKEN"}`);
}

step("Security events (separate from the ledgers; no values).");
say(w.events.events.map((e) => e.detail.event).join(", "));
console.log("");
