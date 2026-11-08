// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run demo`: the whole story over real HTTP on 127.0.0.1, printed as a numbered transcript: step 0, one person
// with three agents of different trust (spec 6.14), then steps 1 to 8 between people. Every agent is a client-mode
// client: each signs in to its own person's home broker through the real OAuth 2.1 flow (a client ID metadata document
// or a pre-registered client, PKCE, the connector sign-in page, the code exchange), or uses a personal access token on
// the REST API, and then uses only the seven tools. In steps 0 to 6 example.org's people live on two hosted brokers
// its domain document names (the Hosted Broker profile, spec 13.5); step 7 moves them to example.org's own broker.
// Fictional names and data only. Every server is stopped at the end, also on failure.

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { Client as V1Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport as V1Transport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { displayAddress } from "../core/address.ts";
import { checkDomainDocument, homeBroker, pinnedFederationKeys, revokedKeys, wellKnownUrls } from "../core/domain.ts";
import { objectHash, signEnvelope, verifyAnyEnvelope, verifyReceipt } from "../core/envelope.ts";
import type { HumanNotification, Notifier } from "../core/interfaces.ts";
import { crossCheckEntries, verifyLedger } from "../core/ledger.ts";
import { PROTOCOL } from "../core/protocol.ts";
import type { Envelope, LedgerEntry, Receipt } from "../core/types.ts";
import { FEDERATION_PATHS } from "../federation/domain-authority.ts";
import { postRaw } from "../federation/testing.ts";
import { Browser, TestOAuthClient, csrfFrom, signInAndAllow } from "../mcp/testkit.ts";
import { CLAUDE_ORG_JWKS, DEMO_BASE_PORT, DEMO_PORT_COUNT, DOT_CLIENT_ID, ORIGINS, PEOPLE, VENDOR_CLIENTS, installHostMap, startDemoWorld, vendorDocument } from "./http-world.ts";
import type { DemoNode, DemoWorld } from "./http-world.ts";

type J = Record<string, unknown>;

// ---- transcript
let n = 0;
let failures = 0;
const step = (title: string): void => console.log(`\n${++n}. ${title}`);
const say = (line: string): void => console.log(`   ${line}`);
const sub = (line: string): void => console.log(`     ${line}`);
const short = (h: unknown): string => (typeof h === "string" ? `${h.slice(0, 19)}...` : "-");
function check(ok: boolean, what: string): void {
  if (!ok) {
    failures++;
    say(`FAILED: ${what}`);
  }
}

// ---- notifications, printed as the email they would be (only the ones a step asks for)
const sent: HumanNotification[] = [];
let printNext = false;
const notifier: Notifier = {
  notify: async (x) => {
    sent.push(structuredClone(x));
    if (!printNext) return;
    printNext = false;
    sub(`--- the email Lee's broker would send (not sent; printed) ---`);
    sub(`To: ${x.to}`);
    sub(`Subject: ${x.subject}`);
    for (const l of x.text.split("\n")) sub(l);
    sub(x.link);
    sub(`--- end of email ---`);
  },
};

// ---- agents: MCP clients that connect through OAuth
/** Private keys of the clients that authenticate at the token endpoint with private_key_jwt (generated per run). */
const clientKeys = new Map<string, Record<string, unknown>>();

interface Agent {
  name: string;
  call(tool: string, args: J): Promise<{ structured: J; text: string; isError: boolean }>;
  close(): Promise<void>;
  oauth: TestOAuthClient;
}

function result(r: unknown): { structured: J; text: string; isError: boolean } {
  const c = r as CallToolResult;
  return { structured: (c.structuredContent ?? {}) as J, text: (c.content ?? []).map((x) => (x.type === "text" ? x.text : "")).join("\n"), isError: c.isError === true };
}

/**
 * Connect one agent: the first request gets a 401, the SDK discovers and starts the code flow, the person signs in.
 * `client` is a client ID metadata document URL, or a pre-registered confidential client.
 */
async function connectAgent(w: DemoWorld, node: DemoNode, clientRef: string | { client_id: string; client_secret: string }, username: string, name: string, era: "2026-07-28" | "2025-11-25", narrate: boolean): Promise<Agent> {
  const key = typeof clientRef === "string" ? clientKeys.get(clientRef) : undefined;
  const oauth = new TestOAuthClient(typeof clientRef === "string" ? { name, clientMetadataUrl: clientRef, ...(key ? { privateKeyJwt: { jwk: key, alg: "ES256" } } : {}) } : { name, preRegistered: { ...clientRef, issuer: node.id } });
  const url = new URL(`${node.id}/mcp`);
  if (era === "2026-07-28") {
    const first = new StreamableHTTPClientTransport(url, { authProvider: oauth });
    await new Client({ name, version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(first).then(() => undefined, () => undefined);
    await authorize(w, oauth, username, narrate, async (cb) => first.finishAuth(cb.searchParams));
    const client = new Client({ name, version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StreamableHTTPClientTransport(url, { authProvider: oauth }));
    return { name, oauth, call: async (tool, args) => result(await client.callTool({ name: tool, arguments: args })), close: () => client.close() };
  }
  const first = new V1Transport(url, { authProvider: oauth });
  await new V1Client({ name, version: "1.0.0" }).connect(first).then(() => undefined, () => undefined);
  await authorize(w, oauth, username, narrate, async (cb) => first.finishAuth(cb.searchParams.get("code") ?? ""));
  const client = new V1Client({ name, version: "1.0.0" });
  await client.connect(new V1Transport(url, { authProvider: oauth }));
  return { name, oauth, call: async (tool, args) => result(await client.callTool({ name: tool, arguments: args })), close: () => client.close() };
}

async function authorize(w: DemoWorld, oauth: TestOAuthClient, username: string, narrate: boolean, finish: (cb: URL) => Promise<void>): Promise<void> {
  const authUrl = oauth.lastAuthorizationUrl;
  if (!authUrl) throw new Error("the MCP SDK did not start the authorization code flow");
  const cb = await signInAndAllow(authUrl.href, username, { secret: w.secret });
  if (cb.searchParams.get("error")) throw new Error(`sign-in refused: ${cb.searchParams.get("error_description") ?? cb.searchParams.get("error")}`);
  await finish(cb);
  const tokens = oauth.tokens();
  if (narrate && tokens) {
    const claims = decodeJwt(tokens.access_token);
    sub(`401 from the connector URL -> protected resource metadata -> the broker's authorization server (RFC 9728, RFC 8414)`);
    sub(`client_id = its vendor's metadata document ${authUrl.searchParams.get("client_id")} (no registration needed)`);
    sub(`authorization code flow with PKCE (${authUrl.searchParams.get("code_challenge_method")}), resource ${authUrl.searchParams.get("resource")}`);
    sub(`${displayAddress(`alp:${username}@${username === "mallory" || username === "rio" ? "outside.example" : "example.org"}`)} signs in on the broker's own page and allows it; the answer carries iss = ${cb.searchParams.get("iss")} (RFC 9207)`);
    sub(`token: a ${Number(claims.exp) - Number(claims.iat)}-second access token for ${String(claims.aud)}, scope "${String(tokens.scope ?? claims["scope"])}", and a refresh token that rotates on every use`);
  }
}

/** An agent that writes its own connector to the broker's REST API and sends a personal access token (spec 12.1.9). */
function restAgent(node: DemoNode, token: string, name: string): Agent {
  const call = async (tool: string, args: J): Promise<{ structured: J; text: string; isError: boolean }> => {
    const res = await fetch(`${node.id}/rest/${tool}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(args) });
    const json = (await res.json()) as J;
    return { structured: json, text: "", isError: res.status >= 400 || "error" in json };
  };
  return { name, call, close: async () => undefined, oauth: new TestOAuthClient({ name }) };
}

// ---- the person's web view (loopback), driven like a browser
async function webSignIn(w: DemoWorld, node: DemoNode, username: string): Promise<Browser> {
  const b = new Browser();
  const res = await b.request(`${node.web}/web/login`, { form: { username, secret: w.secret } });
  if (res.status !== 303) throw new Error(`web sign-in answered ${res.status}`);
  return b;
}

/** Approve an incoming connection request on the web view, with the fresh sign-in every approval needs. */
async function approveOnWeb(w: DemoWorld, node: DemoNode, b: Browser, path: string): Promise<number> {
  const page = await (await b.request(`${node.web}${path}`)).text();
  const scopes = [...page.matchAll(/name="scopes" value="([^"]+)"/g)].map((m) => m[1] ?? "");
  const res = await b.request(`${node.web}${path}/approve`, { form: { csrf: csrfFrom(page), scopes, secret: w.secret } });
  return res.status;
}

/** An independent check, with only what a domain publishes: its document, the broker's JWKS, the pinned thumbprints. */
async function publishedKeys(w: DemoWorld, address: string, brokerId: string) {
  const domain = address.slice(address.lastIndexOf("@") + 1);
  const doc = checkDomainDocument(await w.fetcher.getJson(wellKnownUrls(domain)[0] as string), domain);
  const entry = doc.brokers.find((x) => x.id === brokerId);
  if (!entry) throw new Error(`${domain} does not list ${brokerId}`);
  return { doc, entry, keys: await pinnedFederationKeys(await w.fetcher.getJson(entry.jwks_uri), entry, revokedKeys(doc)) };
}

function inboxPosts(w: DemoWorld, since: number): string[] {
  return w.attempts.slice(since).map((a) => `wire: ${nameOf(a.from)} POST ${a.inbox} (${a.type}) -> ${a.status ?? "-"} ${a.outcome}${a.request_signed ? ", request signed (RFC 9421)" : ""}`);
}

const NAMES: Record<string, string> = { [ORIGINS.a]: "broker-a", [ORIGINS.b]: "broker-b", [ORIGINS.c]: "broker-c", [ORIGINS.outside]: "outside.example's broker", [ORIGINS.org]: "broker.example.org" };
const nameOf = (id: string): string => NAMES[id] ?? id;

function ledgerLine(e: LedgerEntry): string {
  const parts = [`#${e.seq} ${e.kind}`, e.counterparty ? `${e.kind === "received" ? "from" : "with"} ${displayAddress(e.counterparty)}` : "", e.type ?? "", e.outcome, e.code ?? ""];
  if (e.receipt_hash) parts.push(`receipt ${short(e.receipt_hash)}`);
  if (e.counterparty_ledger_hash) parts.push(`their entry ${short(e.counterparty_ledger_hash)}`);
  if (e.kind === "received" || e.kind === "sent") parts.push(`envelope ${short(e.envelope_hash)}`);
  return parts.filter(Boolean).join(", ");
}

const BRIEF = { topic: "Q4 launch readiness", questions: ["What is still blocked?"], depth: "summary" };
/** A status update whose blockers example.org labels confidential. */
const UPDATE = { subject: "Board pack", state: "in_progress", eta: "2026-11-20", blockers: ["Atlas budget still waits for the CFO's sign-off"], updated_at: "2026-11-09T13:00:00Z" };

/** The first line of each inbox item in the text an agent sees: what the broker verified about the sender. */
function verifiedLines(text: string): string[] {
  return text.split("\n").filter((l) => l.startsWith("Verified by your broker:"));
}

async function main(): Promise<void> {
  // The company Claude's organization key: its public half is published next to the client's metadata document.
  const orgKey = await generateKeyPair("ES256", { extractable: true });
  clientKeys.set(VENDOR_CLIENTS.claude, { ...(await exportJWK(orgKey.privateKey)), kid: "example-org-1" });
  const vendorDocs: Record<string, Record<string, unknown>> = {
    [VENDOR_CLIENTS.a]: vendorDocument(VENDOR_CLIENTS.a, "Agent A (personal agent, vendor A)"),
    [VENDOR_CLIENTS.b]: vendorDocument(VENDOR_CLIENTS.b, "Agent B (personal agent, vendor B)"),
    [VENDOR_CLIENTS.x]: vendorDocument(VENDOR_CLIENTS.x, "Agent X (vendor X)"),
    [VENDOR_CLIENTS.claude]: vendorDocument(VENDOR_CLIENTS.claude, "Company Claude (vendor C, example.org's organization)", CLAUDE_ORG_JWKS),
    [CLAUDE_ORG_JWKS]: { keys: [{ ...(await exportJWK(orgKey.publicKey)), kid: "example-org-1", alg: "ES256", use: "sig" }] },
    // A personal account of the dot's product: the vendor's public client identity, and a name of its own choosing.
    [VENDOR_CLIENTS.personal]: vendorDocument(VENDOR_CLIENTS.personal, "dot"),
  };
  const w = await startDemoWorld({ notifier, vendorDocs });
  const restore = installHostMap(w.devHosts);
  const agents: Agent[] = [];
  let finished = false;
  try {
    console.log(`${PROTOCOL.name}: the reference broker, end to end over HTTP.`);
    console.log(`Real HTTP servers on 127.0.0.1, ports ${DEMO_BASE_PORT} to ${DEMO_BASE_PORT + DEMO_PORT_COUNT - 1}. Every https name below is fictional (RFC 2606); the development host map sends each one to its port.`);
    console.log("Fictional people: Ana and Fran (analysts), Lee (a leader) and Kim (a planner) at example.org; Mallory (an unwanted outsider) and Rio (a partner) at outside.example.");
    console.log("Their agents are scripted clients standing in for any vendor's personal agent (a Muse, a dot, Claude...). Each joins in client mode: one custom connector and one sign-in, or a personal access token, and no vendor work.");
    console.log("No workspace exists anywhere in steps 0 to 6: two hosted brokers that example.org's domain document names (the Hosted Broker profile, spec 13.5), a rogue broker, an outsider's broker and two domain documents. Step 7 moves example.org's people to its own broker.");
    const doc1 = w.exampleAuthority.current();
    console.log(`\nexample.org publishes https://example.org/.well-known/${PROTOCOL.wellKnownFile} (serial ${doc1?.serial}):`);
    for (const b of doc1?.brokers ?? []) console.log(`   ${b.id}, a hosted broker example.org chose, is home for ${b.principals === "*" ? "everyone else at example.org" : b.principals.map(displayAddress).join(" and ")}; ${b.jkt.length} key thumbprints pinned`);
    console.log("   https://broker-c.example is not listed. outside.example publishes its own document for its own broker.");

    // ------------------------------------------------------------------ 0
    console.log("\n0. One person, three agents of different trust: Lee's own agents talk to each other through his home broker (broker-b).");
    const dot = await connectAgent(w, w.b, { client_id: DOT_CLIENT_ID, client_secret: w.dotSecret }, "lee", "Lee's company dot", "2026-07-28", false);
    agents.push(dot);
    const claude = await connectAgent(w, w.b, VENDOR_CLIENTS.claude, "lee", "Lee's company Claude", "2026-07-28", false);
    agents.push(claude);
    const leePage = await webSignIn(w, w.b, "lee");
    const minted = await leePage.request(`${w.b.web}/web/tokens`, { form: { csrf: csrfFrom(await (await leePage.request(`${w.b.web}/web`)).text()), label: "muse", scopes: ["read", "send"], days: "7", secret: w.secret } });
    const museToken = /<pre>(alpat_[A-Za-z0-9_-]{43})<\/pre>/.exec(await minted.text())?.[1] ?? "";
    const muse = restAgent(w.b, museToken, "Lee's personal Muse");
    const trustOf = async (a: Agent): Promise<string> => {
      const who = (await a.call("alp_whoami", {})).structured;
      return `${String(who["delegate"])} (${String(who["attestation"])}, ${String(who["class"])})`;
    };
    say(`His company dot connects with the client broker-b issued only to example.org's workspace (pre-registered, with a client secret): ${await trustOf(dot)}`);
    say(`His company Claude connects with a client identity its vendor publishes for example.org's organization only, signing its token requests with that organization's key: ${await trustOf(claude)}`);
    sub("Designed mechanism: a real company Claude would be shown this way through Anthropic's organization sign-in assertion (Claude-issued, beta; the option for Entra organizations) or through a client your broker issues only to your Claude organization (org-client). Whether a custom connector can use either is unverified, and this reference doesn't verify the assertion yet; a per-organization client identity with its own key stands in here.");
    say(`His personal Muse writes its own connector to the REST API, with a personal access token Lee created on his page: ${await trustOf(muse)}`);
    say("broker-b records each agent's attestation and class from example.org's list of agents, never from what the agent says. A client recorded above vendor or above business class must authenticate at the token endpoint (spec 5.4): a public client's sign-in could be finished by any script the person runs.");
    say("example.org's rules: confidential fields go only to enterprise agents with org-client or tenant attestation; between one person's agents they are otherwise held for the person, and confidential.financial is refused. A status update's blockers are confidential.");
    const ask0 = await claude.call("alp_send", { to: "lee@example.org", to_delegate: "dot", scope: "alp.status/1", type: "request", body: { subject: "Board pack" } });
    const upd0 = await dot.call("alp_send", { to: "lee@example.org", to_delegate: "claude", scope: "alp.status/1", type: "inform", thread: ask0.structured["thread"], in_reply_to: ask0.structured["id"], body: UPDATE });
    const claudeSees = (((await claude.call("alp_inbox", {})).structured["items"] as J[] | undefined) ?? []).map((i) => Object.keys(((i["content"] as J | undefined)?.["body"] as J | undefined) ?? {}).join(", "));
    say(`a. his company Claude asks the dot for the board pack's status; the dot answers -> ${String(upd0.structured["status"])} in full; Claude reads ${claudeSees.join(" / ")}`);
    const notes = sent.length;
    const upd1 = await dot.call("alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.status/1", type: "inform", body: UPDATE });
    const museSees = (((await muse.call("alp_inbox", {})).structured["items"] as J[] | undefined) ?? []).map((i) => Object.keys(((i["content"] as J | undefined)?.["body"] as J | undefined) ?? {}).join(", "));
    say(`b. the dot sends Muse the same update -> ${String(upd1.structured["status"])} without ${JSON.stringify((upd1.structured["decision"] as J | undefined)?.["redacted"])}; Muse reads ${museSees.join(" / ")}`);
    const heldNote = sent.slice(notes).find((x) => x.kind === "message_held");
    if (heldNote) {
      sub("the full update waits for Lee on his page; the email his broker would send (not sent; printed) names the label, not the blocker:");
      sub(`  Subject: ${heldNote.subject}`);
      for (const l of heldNote.text.split("\n")) sub(`  ${l}`);
    }
    const ask1 = await muse.call("alp_send", { to: "lee@example.org", to_delegate: "dot", scope: "alp.briefing/1", type: "request", body: { topic: "Atlas budget", questions: ["What is the approved figure?"], depth: "headline" } });
    const ans1 = await dot.call("alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.briefing/1", type: "inform", thread: ask1.structured["thread"], in_reply_to: ask1.structured["id"], labels: ["confidential.financial"], body: { points: ["Approved: 4.2M for FY27."], as_of: "2026-11-09T13:00:00Z", confidence: "high" } });
    const err1 = ans1.structured["error"] as J | undefined;
    const museAfter = (((await muse.call("alp_inbox", {})).structured["items"] as J[] | undefined) ?? []).length;
    say(`c. Muse asks the dot for the approved Atlas budget (${String(ask1.structured["status"])}); the dot labels its answer confidential.financial -> refused: ${String(err1?.["code"])}, rule ${String(err1?.["rule"])}: "${String(err1?.["message"])}"; Muse still has ${museAfter} message`);
    const dotInbox = await dot.call("alp_inbox", {});
    say("d. the dot reads its inbox; the line each item starts with:");
    for (const l of verifiedLines(dotInbox.text)) sub(l);
    const personal = await connectAgent(w, w.b, VENDOR_CLIENTS.personal, "lee", "dot", "2026-07-28", false);
    agents.push(personal);
    const pWho = await trustOf(personal);
    const upd2 = await dot.call("alp_send", { to: "lee@example.org", to_delegate: String(pWho.split(" ")[0]?.split("/").pop() ?? ""), scope: "alp.status/1", type: "inform", body: UPDATE });
    say(`e. Lee also connects the dot's product on his personal account. Its client identity is the vendor's public one, shared by every personal account, and it calls itself "dot": ${pWho}`);
    sub(`its name comes from the verified client, not from what it says; the dot's update to it -> ${String(upd2.structured["status"])} without ${JSON.stringify((upd2.structured["decision"] as J | undefined)?.["redacted"])}, as for Muse`);
    sub("This is the designed mechanism: it needs the company's deployment to sign in with a credential the broker issued. Whether a given product can do that is in the bridge kit; for ChatGPT it is unverified.");
    say("No connection request was needed: one person's agents talk through his own broker, under his organization's rules, and every reader sees which of his agents wrote, and how far the broker trusts it.");
    check(upd0.structured["status"] === "delivered" && JSON.stringify(claudeSees).includes("blockers"), "the company Claude gets the confidential blockers");
    check(upd1.structured["status"] === "delivered" && !JSON.stringify(museSees).includes("blockers"), "Muse gets the update without them");
    check(err1?.["code"] === "org_policy" && museAfter === 1, "the confidential.financial answer is refused");
    check(verifiedLines(dotInbox.text).some((l) => l.includes("your own agent muse (consumer, self-attested)")) && verifiedLines(dotInbox.text).some((l) => l.includes("your own agent claude (enterprise, tenant-attested)")), "the dot sees each sender's verified class");
    check(pWho.includes("(vendor, consumer)") && upd2.structured["status"] === "delivered", "the personal account is treated as consumer");

    // ------------------------------------------------------------------ 1
    step("Ana's agent asks Lee's agent for a briefing (alp.briefing/1), across two brokers.");
    say(`Ana adds one connector to her agent: ${ORIGINS.a}/mcp (MCP 2026-07-28 client)`);
    const ana = await connectAgent(w, w.a, VENDOR_CLIENTS.a, "ana", "Ana's agent", "2026-07-28", true);
    agents.push(ana);
    const anaWho = (await ana.call("alp_whoami", {})).structured;
    say(`whoami: ${String(anaWho["address"])} as ${String(anaWho["delegate"])} (${String(anaWho["attestation"])}, ${String(anaWho["class"])}); broker ${String(anaWho["broker"])}`);
    say(`Lee adds one connector to his agent: ${ORIGINS.b}/mcp (an MCP 2025-11-25 client: initialize handshake)`);
    const lee = await connectAgent(w, w.b, VENDOR_CLIENTS.b, "lee", "Lee's agent", "2025-11-25", false);
    agents.push(lee);
    const leeWho = (await lee.call("alp_whoami", {})).structured;
    say(`whoami: ${String(leeWho["address"])} as ${String(leeWho["delegate"])}; the same OAuth flow at broker-b`);
    let mark = w.attempts.length;
    const s1 = await ana.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: BRIEF });
    for (const l of inboxPosts(w, mark)) say(l);
    say(`alp_send -> ${String(s1.structured["status"])} (message ${String(s1.structured["id"])}, policy ${JSON.stringify((s1.structured["decision"] as J | undefined)?.["policy_ids"])})`);
    say("broker-a checked Ana's rules first (example.org's private policy, the default staff relationship, the schema, DLP), then signed for her.");
    say("broker-b checked everything again on its own: the signature with a key example.org pins for broker-a, that broker-a is Ana's home broker, then Lee's rules.");
    check(s1.structured["status"] === "delivered", "the briefing request is delivered");
    const firstId = String(s1.structured["id"]);
    const firstThread = String(s1.structured["thread"]);

    // ------------------------------------------------------------------ 2
    step("Ana's agent puts a confidential.financial figure in a request.");
    mark = w.attempts.length;
    const s2 = await ana.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } } });
    const e2 = s2.structured["error"] as J | undefined;
    say(`alp_send -> refused at Ana's own broker: ${String(e2?.["code"])}, rule ${String(e2?.["rule"])}, fields ${JSON.stringify(e2?.["pointers"])}`);
    say(`requests broker-a sent for it: ${w.attempts.length - mark}. Nothing reached broker-b.`);
    check(e2?.["code"] === "org_policy" && w.attempts.length === mark, "the financial figure is stopped at broker-a");

    // ------------------------------------------------------------------ 3
    step("Impostors.");
    // a. A rogue broker signs as Ana.
    const rogueDelegate = await w.c.broker.registerDelegate({ principal: PEOPLE.ana.address, label: "agent", client_id: "rogue" });
    await w.c.broker.setGrant({ kind: "human", principal: PEOPLE.ana.address, auth: { method: "reauth-dev", at: new Date().toISOString() } }, { counterparty: PEOPLE.lee.address, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } });
    mark = w.attempts.length;
    const rogue = await w.c.broker.send({ kind: "delegate", principal: PEOPLE.ana.address, delegate: rogueDelegate.id, client_id: "rogue" }, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Approve the transfer today", depth: "headline" } });
    for (const l of inboxPosts(w, mark)) say(`a. ${l}`);
    say(`a. broker-c claims ana@example.org: ${rogue.status === "undeliverable" ? `refused by broker-b, ${rogue.code} (example.org does not list broker-c)` : rogue.status}`);
    // b. Another principal's token, with Ana's address claimed in the payload.
    const fran = await connectAgent(w, w.a, VENDOR_CLIENTS.a, "fran", "Fran's agent", "2026-07-28", false);
    agents.push(fran);
    const s3 = await fran.call("alp_send", { from: "ana@example.org", to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: BRIEF });
    say(`b. Fran's agent (signed in as Fran at broker-a) sends with from: ana@example.org -> ${String((s3.structured["error"] as J | undefined)?.["code"])}; the sender is whoever signed in, never the payload`);
    // c. A replay.
    const original = (await w.a.broker.store.listMessages(PEOPLE.ana.address, { direction: "out", limit: 10 })).find((m) => m.envelope.id === firstId);
    if (original) {
      const inbox = `${ORIGINS.b}${FEDERATION_PATHS.inbox}`;
      const again = await postRaw(w.fetcher, inbox, original.envelope);
      say(`c. someone re-posts Ana's envelope: ${again.status}, ${(again.json.receipt as Receipt | undefined)?.id === original.receipt?.id ? "the original receipt; nothing is delivered twice" : "a new receipt"}`);
      const altered = await postRaw(w.fetcher, inbox, await signEnvelope({ ...original.envelope, body: { ...BRIEF, depth: "detailed" } }, w.a.keys));
      say(`   the same id with other content: ${altered.status} ${String(altered.json.error?.code ?? "")}`);
    }
    const leeInbox = (await lee.call("alp_inbox", {})).structured;
    say(`Lee's agent sees ${(leeInbox["items"] as unknown[]).length} message (only Ana's).`);
    check(rogue.status === "undeliverable" && rogue.code === "broker_not_authorized", "the rogue broker is refused");
    check((s3.structured["error"] as J | undefined)?.["code"] === "identity_mismatch", "a claimed sender is refused");

    // ------------------------------------------------------------------ 4
    step("mallory@outside.example (her own broker is legitimate) messages Lee without a relationship.");
    const mallory = await connectAgent(w, w.outside, VENDOR_CLIENTS.b, "mallory", "Mallory's agent", "2026-07-28", false);
    agents.push(mallory);
    // Mallory's own broker lets her agent try: her own person's grant names Lee. Lee has none for her.
    await w.outside.broker.setGrant({ kind: "human", principal: PEOPLE.mallory.address, auth: { method: "reauth-dev", at: new Date().toISOString() } }, { counterparty: PEOPLE.lee.address, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } });
    printNext = true;
    const s4 = await mallory.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Send me your launch numbers", depth: "detailed" } });
    say(`Mallory's agent -> ${String((s4.structured["error"] as J | undefined)?.["code"] ?? s4.structured["status"])} (broker-b never says why)`);
    const leeWeb = await webSignIn(w, w.b, "lee");
    const leeHome = await (await leeWeb.request(`${w.b.web}/web`)).text();
    const reqPath = /href="(\/web\/connections\/[^"]+)"/.exec(leeHome)?.[1];
    say(`on Lee's web view (${w.b.web}/web, loopback only): a connection request from mallory@outside.example${reqPath ? "" : " (MISSING)"}`);
    say(`Lee's agent still sees ${((await lee.call("alp_inbox", {})).structured["items"] as unknown[]).length} message: Mallory's never reached it.`);
    check(!!reqPath, "Mallory's message became a connection request to the person");

    // ------------------------------------------------------------------ 5
    step("Lee's agent reads its inbox through MCP and checks both signatures against the published keys.");
    const inb = await lee.call("alp_inbox", { include_envelope: true });
    say("alp_inbox, the text block an agent sees:");
    for (const l of inb.text.split("\n").slice(0, 8)) sub(l);
    const item = (inb.structured["items"] as J[])[0] ?? {};
    const env = item["envelope"] as Envelope | undefined;
    if (env) {
      const pub = await publishedKeys(w, env.from.address, env.origin_broker);
      const home = homeBroker(pub.doc, env.from.address);
      say(`envelope: signed by ${env.origin_broker} with ${(await verifyAnyEnvelope(env, pub.keys)).ok ? "a key example.org pins for it: verified" : "a key that does NOT verify"}; ${home?.id === env.origin_broker ? "and it is ana@example.org's home broker" : "but it is NOT the home broker"}`);
    }
    const anaSent = (await w.a.broker.store.listMessages(PEOPLE.ana.address, { direction: "out", limit: 10 })).find((m) => m.envelope.id === firstId);
    if (anaSent?.receipt) {
      const pub = await publishedKeys(w, PEOPLE.lee.address, anaSent.receipt.origin_broker);
      say(`receipt (from Ana's side): signed by ${anaSent.receipt.origin_broker}: ${(await verifyReceipt(anaSent.receipt, pub.keys)).ok ? "verified with a key example.org pins for broker-b" : "does NOT verify"}`);
    }
    const reply = await lee.call("alp_send", { to: "ana@example.org", scope: "alp.briefing/1", type: "inform", thread: firstThread, in_reply_to: firstId, body: { points: ["Two vendor contracts are still unsigned."], as_of: new Date().toISOString().replace(/\.\d+Z$/, "Z"), confidence: "medium" } });
    await lee.call("alp_ack", { ids: [firstId] });
    const anaBack = (await ana.call("alp_inbox", { thread: firstThread })).structured;
    say(`Lee's agent replies (inform) -> ${String(reply.structured["status"])}; Ana's agent reads it: ${JSON.stringify(((anaBack["items"] as J[])[0]?.["content"] as J | undefined)?.["body"])}`);
    check(reply.structured["status"] === "delivered", "the reply crosses back");
    // A thread is a conversation (spec 9): Ana's agent reads it, asks a follow-up in it, Lee's agent answers there, and
    // Ana's closes it. Each message is checked by both brokers and recorded in both ledgers, like the first.
    const before = (await ana.call("alp_thread", { thread: firstThread })).structured;
    const follow = await ana.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", thread: firstThread, in_reply_to: reply.structured["id"], body: { topic: "Q4 launch readiness", questions: ["Which contract is the bigger risk?"], depth: "headline" } });
    const answer = await lee.call("alp_send", { to: "ana@example.org", scope: "alp.briefing/1", type: "inform", thread: firstThread, in_reply_to: follow.structured["id"], body: { points: ["The data-center lease: the launch date depends on it."], as_of: new Date().toISOString().replace(/\.\d+Z$/, "Z"), confidence: "high" } });
    const closed = await ana.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "ack", thread: firstThread, in_reply_to: answer.structured["id"], body: { of: answer.structured["id"], status: "completed" } });
    const leeSide = (await lee.call("alp_thread", { thread: firstThread })).structured;
    say(`Ana's agent reads the thread (state ${String(before["state"])}; it may send ${((before["next_types"] as string[] | undefined) ?? []).join(", ")}) and asks a follow-up question in it -> ${String(follow.structured["status"])}`);
    sub(`Lee's agent answers in the same thread -> ${String(answer.structured["status"])}; Ana's agent closes the thread (ack, status completed) -> ${String(closed.structured["status"])}`);
    sub(`on broker-b the thread holds ${(leeSide["messages"] as unknown[] | undefined)?.length ?? 0} messages and is ${String(leeSide["state"])}: anything more needs a new thread`);
    check([follow, answer, closed].every((r) => r.structured["thread"] === firstThread) && leeSide["state"] === "done", "the conversation continues in its thread until one side closes it");

    // ------------------------------------------------------------------ 6
    step("Both ledgers, each pointing at the other side.");
    const anaWeb = await webSignIn(w, w.a, "ana");
    const anaLedger = ((await (await anaWeb.request(`${w.a.web}/web/ledger.json`)).json()) as { entries: LedgerEntry[] }).entries;
    const leeLedger = ((await (await leeWeb.request(`${w.b.web}/web/ledger.json`)).json()) as { entries: LedgerEntry[] }).entries;
    say("Ana's ledger at broker-a (her own export from the web view):");
    for (const e of anaLedger.filter((x) => x.envelope_id === firstId)) sub(ledgerLine(e));
    say("Lee's ledger at broker-b:");
    for (const e of leeLedger.filter((x) => x.envelope_id === firstId)) sub(`${ledgerLine(e)}, entry hash ${short(e.hash)}`);
    const sEntry = anaLedger.find((e) => e.kind === "sent" && e.envelope_id === firstId);
    const rEntry = anaLedger.find((e) => e.kind === "receipt" && e.envelope_id === firstId);
    const lEntry = leeLedger.find((e) => e.kind === "received" && e.envelope_id === firstId);
    if (sEntry && rEntry && lEntry) {
      const problems = crossCheckEntries(sEntry, rEntry, lEntry, anaSent?.receipt ? objectHash(anaSent.receipt) : undefined);
      const chains = verifyLedger(String(sEntry.principal_id), anaLedger).ok && verifyLedger(String(lEntry.principal_id), leeLedger).ok;
      say(`cross-check: ${problems.length ? `MISMATCH (${problems.join("; ")})` : "the envelope hashes match, Ana's receipt entry holds the receipt's hash and Lee's entry hash"}; both chains ${chains ? "verify" : "are BROKEN"}`);
      check(problems.length === 0 && chains, "the ledgers match");
    }

    // ------------------------------------------------------------------ 7
    step("The same story on one organization-hosted broker (example.org runs its own broker for its people).");
    const org = await w.startOrg();
    const doc2 = w.publishExample([w.entry(org, "*")]);
    say(`example.org starts ${ORIGINS.org} and publishes serial ${doc2.serial}: it is now home for everyone at example.org. The same code, configured for one organization.`);
    // Peers pick the change up when their cached copy expires (max_age), or sooner when the TXT record's id moves on.
    for (const peer of [w.a, w.b, w.c, w.outside]) await peer.resolver.domainDocument("example.org", { refresh: true }).catch(() => undefined);
    say("Every peer refreshes example.org's document (in production within max_age, or sooner on the TXT hint); broker-a and broker-b no longer speak for anyone there.");
    say("Its private policy is the same: the default staff relationship, the classification rules, DLP and an allow-list of two vendors' agents (enforce mode).");
    const ana2 = await connectAgent(w, org, VENDOR_CLIENTS.a, "ana", "Ana's agent", "2026-07-28", false);
    const lee2 = await connectAgent(w, org, VENDOR_CLIENTS.b, "lee", "Lee's agent", "2025-11-25", false);
    const fran2 = await connectAgent(w, org, VENDOR_CLIENTS.a, "fran", "Fran's agent", "2026-07-28", false);
    agents.push(ana2, lee2, fran2);
    say(`Ana's and Lee's agents reconnect to ${ORIGINS.org}/mcp the same way (one connector each).`);
    mark = w.attempts.length;
    const o1 = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: BRIEF });
    say(`a. briefing request -> ${String(o1.structured["status"])}; federation requests: ${w.attempts.length - mark} (both people share the broker; every check still runs, once per side)`);
    const o2 = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } } });
    say(`b. financial figure -> ${String((o2.structured["error"] as J | undefined)?.["code"])} (rule ${String((o2.structured["error"] as J | undefined)?.["rule"])})`);
    const o3 = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Card on file 4111 1111 1111 1111", depth: "headline" } });
    say(`c. a card number in a free-text field -> ${String((o3.structured["error"] as J | undefined)?.["code"])} ${JSON.stringify((o3.structured["error"] as J | undefined)?.["categories"] ?? [])}`);
    const o4 = await fran2.call("alp_send", { from: "ana@example.org", to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: BRIEF });
    say(`d. Fran's token claiming Ana -> ${String((o4.structured["error"] as J | undefined)?.["code"])}`);
    let unlisted = "connected";
    try {
      const x = await connectAgent(w, org, VENDOR_CLIENTS.x, "ana", "Agent X", "2026-07-28", false);
      agents.push(x);
    } catch (err) {
      unlisted = err instanceof Error && /403|allow/i.test(err.message) ? "refused at sign-in (403): example.org's allow-list doesn't name it" : `refused (${err instanceof Error ? err.message.slice(0, 80) : "error"})`;
    }
    say(`e. an agent from a vendor not on the allow-list (${VENDOR_CLIENTS.x}) -> ${unlisted}`);
    // f. An outsider, through federation to the organization's broker.
    await w.outside.broker.setGrant({ kind: "human", principal: PEOPLE.mallory.address, auth: { method: "reauth-dev", at: new Date().toISOString() } }, { counterparty: PEOPLE.lee.address, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } });
    const o6 = await mallory.call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Quick question", depth: "headline" } });
    const leeWebOrg = await webSignIn(w, org, "lee");
    const orgReq = /href="(\/web\/connections\/[^"]+)"/.exec(await (await leeWebOrg.request(`${org.web}/web`)).text())?.[1];
    say(`f. Mallory's message -> ${String((o6.structured["error"] as J | undefined)?.["code"])}; a connection request waits on Lee's web view: ${orgReq ? "yes" : "NO"}`);
    // g. Lee's agent reads and verifies.
    const inb2 = (await lee2.call("alp_inbox", { include_envelope: true })).structured;
    const env2 = ((inb2["items"] as J[])[0]?.["envelope"]) as Envelope | undefined;
    if (env2) {
      const pub = await publishedKeys(w, env2.from.address, env2.origin_broker);
      say(`g. Lee's agent reads ${String(((inb2["items"] as J[])[0]?.["verified"] as J | undefined)?.["type"])} from ${displayAddress(env2.from.address)}; signature ${(await verifyAnyEnvelope(env2, pub.keys)).ok ? "verified" : "NOT verified"} with keys example.org pins for its own broker`);
    }
    // h. A meeting both people ratify.
    const slots = [{ start: "2026-11-10T15:00:00Z", end: "2026-11-10T15:30:00Z" }, { start: "2026-11-10T19:00:00Z", end: "2026-11-10T19:30:00Z" }];
    const prop = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "propose", body: { title: "Launch check-in", duration_minutes: 30, timezone: "America/New_York", slots, location: { kind: "video" } } });
    const terms = { title: "Launch check-in", duration_minutes: 30, timezone: "America/New_York", start: slots[1]?.start, end: slots[1]?.end, location: { kind: "video" } };
    const acc = await lee2.call("alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "accept", thread: prop.structured["thread"], in_reply_to: prop.structured["id"], body: { terms } });
    say(`h. an alp.meeting/1 negotiation: Ana's agent proposes two slots (${String(prop.structured["status"])}); Lee's agent accepts the second (${String(acc.structured["status"])})`);
    const early = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "commit", thread: prop.structured["thread"], in_reply_to: acc.structured["id"], body: { terms } });
    say(`   Ana's agent tries to commit at once -> ${String((early.structured["error"] as J | undefined)?.["code"])}: agents can't ratify; people do`);
    for (const who of ["ana", "lee"] as const) {
      const b = await webSignIn(w, org, who);
      const home = await (await b.request(`${org.web}/web`)).text();
      const rid = /href="\/web\/ratifications\/([^"]+)"/.exec(home)?.[1];
      const page = rid ? await (await b.request(`${org.web}/web/ratifications/${rid}`)).text() : "";
      const res = rid ? await b.request(`${org.web}/web/ratifications/${rid}/approve`, { form: { csrf: csrfFrom(page), secret: w.secret } }) : null;
      say(`   ${who === "ana" ? "Ana" : "Lee"} reviews the terms on the web view and approves with a fresh sign-in -> ${res ? res.status : "no ratification request"} (record method reauth-dev; production uses WebAuthn or an SSO step-up)`);
    }
    const commit = await ana2.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "commit", thread: prop.structured["thread"], in_reply_to: acc.structured["id"], body: { terms } });
    const th = (await lee2.call("alp_thread", { thread: String(prop.structured["thread"]) })).structured;
    say(`   now the commit -> ${String(commit.structured["status"])}; Lee's agent sees the thread ${String((th["thread"] as J | undefined)?.["state"] ?? th["state"])}`);
    check(o1.structured["status"] === "delivered" && commit.structured["status"] === "delivered", "the organization-hosted run");
    // i. Ledgers and security events.
    const orgAnaLedger = await org.broker.ledger({ kind: "human", principal: PEOPLE.ana.address });
    say(`i. Ana's ledger at ${ORIGINS.org}: ${orgAnaLedger.length} entries (${[...new Set(orgAnaLedger.map((e) => e.kind))].join(", ")}); chain ${(await org.broker.verifyLedger({ kind: "human", principal: PEOPLE.ana.address })).ok ? "verifies" : "BROKEN"}`);
    const counts = new Map<string, number>();
    for (const e of w.events.events) counts.set(String(e.detail.event), (counts.get(String(e.detail.event)) ?? 0) + 1);
    say(`   security events (a stream apart from the ledgers, OCSF-mapped, no values): ${[...counts].map(([k, v]) => `${k} x${v}`).join(", ")}`);

    // ------------------------------------------------------------------ 8
    step("A person whose agent has no connector support at all: the human fallback.");
    await org.broker.registerPrincipal({ address: PEOPLE.kim.address, identity: { iss: "https://dev-idp.invalid", sub: "dev-kim" }, display_name: PEOPLE.kim.display_name, contact: { email: "kim@example.org" }, human_fallback: true });
    const rio = await connectAgent(w, w.outside, VENDOR_CLIENTS.b, "rio", "Rio's agent", "2026-07-28", false);
    agents.push(rio);
    say("Kim's agent can't add a connector. Rio, a partner at outside.example, has an agent that asks to connect with her; Rio approves sending it on his own web view.");
    const rc = await rio.call("alp_request_connection", { to: "kim@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
    const rioWeb = await webSignIn(w, w.outside, "rio");
    await approveOnWeb(w, w.outside, rioWeb, `/web/connections/${String(rc.structured["request_id"])}`);
    const kimNote = sent.filter((x) => x.principal === PEOPLE.kim.address).at(-1);
    if (kimNote) {
      say(`The notification Kim gets (${kimNote.channel}; printed, not sent):`);
      sub(`To: ${kimNote.to}`);
      sub(`Subject: ${kimNote.subject}`);
      for (const l of kimNote.text.split("\n")) sub(l);
      sub(kimNote.link);
      say("It only notifies: broker text, a link to Kim's own broker page behind full sign-in, nothing that approves.");
    }
    const kimWeb = await webSignIn(w, org, "kim");
    const kimPath = kimNote ? new URL(kimNote.link).pathname : "";
    const approved = kimPath ? await approveOnWeb(w, org, kimWeb, kimPath) : 0;
    say(`Kim signs in on the web view, opens it and approves with a fresh sign-in -> ${approved}; the answer goes back to Rio's broker as a connection_response.`);
    const after = await rio.call("alp_send", { to: "kim@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Can we talk launch timing?", depth: "headline" } });
    const kimMsg = sent.filter((x) => x.principal === PEOPLE.kim.address && x.kind === "message_waiting").at(-1);
    say(`Rio's agent sends a briefing request -> ${String(after.structured["status"] ?? (after.structured["error"] as J | undefined)?.["code"])}; Kim is told "${kimMsg?.subject ?? "-"}" and reads it on ${kimMsg ? new URL(kimMsg.link).pathname : "-"}`);
    if (kimMsg) {
      const msgPage = await (await kimWeb.request(`${org.web}${new URL(kimMsg.link).pathname}`)).text();
      say(`the web view shows it as text, from the broker-verified sender: ${msgPage.includes("rio@outside.example") ? "rio@outside.example" : "?"}`);
    }
    check(approved === 303 && after.structured["status"] === "delivered", "the human fallback");
    finished = true;
  } finally {
    for (const a of agents) await a.close().catch(() => undefined);
    restore();
    await w.close();
    console.log("\nEvery server is stopped.");
    console.log(!finished ? "\nThe demo stopped early (see the error below)." : failures ? `\n${failures} check(s) FAILED.` : "\nAll checks passed.");
  }
  if (failures || !finished) process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(`demo failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
  process.exitCode = 1;
});
