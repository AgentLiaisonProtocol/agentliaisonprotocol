// SPDX-License-Identifier: FSL-1.1-ALv2
// A hosted broker's web view and sign-in, end to end over HTTP, on Postgres: PGlite (Postgres compiled to
// WebAssembly, in this process) behind the wire-protocol bridge, or ALP_TEST_POSTGRES_URL. The bridge and the brokers
// take loopback ports from the tests' pool (src/test-ports.ts). Passkeys come from a software authenticator
// (webauthn-testkit.ts).
//
// What it shows:
// - sign-in per invited person (invites with expiry and revocation), then a passkey before anything else;
// - every later sign-in, and every approval, ratification, grant change and token, needs a fresh passkey assertion
//   with user verification over the hash of exactly what the page showed (a changed form or changed terms fail);
// - __Host- cookies (Secure, HttpOnly, SameSite=Strict); CSRF, Origin and Sec-Fetch-Site checks; a strict CSP; the
//   15-minute idle timeout; a notice on sign-in from a new browser; request and failed-sign-in limits;
// - the connector sign-in asks for the passkey too, over a challenge bound to that authorization;
// - two instances behind one address share sessions, challenges, tokens, rate windows and refresh-token reuse.

import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import type { Server } from "node:http";
import { after, before, describe, test } from "node:test";
import postgres from "postgres";
import { Client, StreamableHTTPClientTransport, refreshAuthorization } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { Broker } from "../core/broker.ts";
import { KeyRing } from "../core/keys.ts";
import { MemorySecurityEvents } from "../core/security-events.ts";
import type { HumanCaller, ScopeTerms } from "../core/types.ts";
import { DEV_BROKER_ID, DEV_DOMAINS, LOCAL_ONLY_TRANSPORT, devPolicy } from "../dev-world.ts";
import { StaticResolver } from "../federation/static-resolver.ts";
import { Browser, TestOAuthClient, csrfFrom } from "../mcp/testkit.ts";
import { generateAuthServerKeys } from "../oauth/keys.ts";
import { startBrokerServer } from "../server.ts";
import type { RunningBrokerServer } from "../server.ts";
import { startPgliteBridge } from "../storage/pglite-bridge.ts";
import { onFreePorts } from "../test-ports.ts";
import type { PgliteBridge } from "../storage/pglite-bridge.ts";
import { createPostgresStore } from "../storage/postgres.ts";
import type { PostgresStore } from "../storage/postgres.ts";
import { PostgresBindingStore } from "../storage/postgres-binding.ts";
import { InviteIdentityVerifier, createInvite, revokeInvite } from "./invites.ts";
import { ConsoleOutboxNotifier } from "./notifier.ts";
import { SoftAuthenticator } from "./webauthn-testkit.ts";

type J = Record<string, unknown>;

interface Hosted {
  base: string;
  /** The public port, and each instance's (the same one when there is a single instance). */
  ports: { public: number; instances: number[] };
  brokers: Broker[];
  stores: PostgresStore[];
  binding: PostgresBindingStore;
  servers: RunningBrokerServer[];
  notifier: ConsoleOutboxNotifier;
  skew: { ms: number };
  /** Requests each instance served (through the round-robin proxy). */
  hits: Map<number, number>;
  invite(username: string, opts?: { days?: number; email?: string }): Promise<{ id: string; secret: string }>;
  close(): Promise<void>;
}

/** A load balancer in front of several instances: every request goes to the next one, Host kept. */
async function roundRobin(port: number, targets: number[], hits: Map<number, number>): Promise<Server> {
  let i = 0;
  const s = createServer((req, res) => {
    const target = targets[i++ % targets.length] ?? 0;
    hits.set(target, (hits.get(target) ?? 0) + 1);
    const up = httpRequest({ host: "127.0.0.1", port: target, method: req.method, path: req.url, headers: req.headers }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    });
    up.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(up);
  });
  await new Promise<void>((resolve, reject) => {
    s.once("error", reject);
    s.listen(port, "127.0.0.1", () => resolve());
  });
  return s;
}

/** `instances` brokers on one Postgres schema, on ports from the tests' pool, behind one round-robin address when there are several. */
async function startHosted(url: string, schema: string, instances: number, opts: { postsPerMinute?: number } = {}): Promise<Hosted> {
  return onFreePorts(instances > 1 ? instances + 1 : 1, (pool) => {
    const [first = 0, ...rest] = pool;
    return startHostedOn(url, schema, { public: first, instances: instances > 1 ? rest : [first] }, opts);
  });
}

async function startHostedOn(url: string, schema: string, ports: { public: number; instances: number[] }, opts: { postsPerMinute?: number }): Promise<Hosted> {
  const base = `http://127.0.0.1:${ports.public}`;
  const authKeys = await generateAuthServerKeys();
  const notifier = new ConsoleOutboxNotifier();
  const events = new MemorySecurityEvents();
  const skew = { ms: 0 };
  const clock = { now: () => new Date(Date.now() + skew.ms) };
  const hits = new Map<number, number>();
  const stores: PostgresStore[] = [];
  const brokers: Broker[] = [];
  const servers: RunningBrokerServer[] = [];
  const closeAll = async (): Promise<void> => {
    for (const s of servers) await s.close();
    for (const s of stores) await s.close();
  };
  let proxy: Server | undefined;
  try {
    for (const port of ports.instances) {
      // Each instance has its own pool, as separate processes would.
      const store = await createPostgresStore({ url, schema, max: 2 });
      stores.push(store);
      const binding = new PostgresBindingStore(store.sql);
      const stored = await store.getKeyRing("federation");
      let keys: KeyRing;
      if (stored) keys = KeyRing.fromJSON(stored);
      else {
        keys = await KeyRing.generate(new Date());
        await keys.prepareNext(new Date());
        await store.putKeyRing("federation", keys.toJSON());
      }
      const policies = [devPolicy(new Date())];
      // The broker's id is its https origin; here the public URL is a loopback http one, as in the other client-binding tests.
      const broker = new Broker({ id: DEV_BROKER_ID, store, keys, resolver: new StaticResolver(), transport: LOCAL_ONLY_TRANSPORT, notifier, policies, domains: DEV_DOMAINS, securityEvents: events, webBaseUrl: `${base}/web` });
      brokers.push(broker);
      servers.push(
        await startBrokerServer({
          broker,
          publicUrl: base,
          port,
          identity: new InviteIdentityVerifier(binding, base, clock),
          idpMode: "dev",
          requireSecret: true,
          policies: () => policies,
          notifier,
          bindingStore: binding,
          windows: store,
          authKeys,
          publicWeb: { rpName: "ALP test broker", postsPerMinute: opts.postsPerMinute ?? 10_000 },
          // A request may say where it comes from in X-Real-IP, as behind a proxy that sets it; without it, the socket.
          clientIpHeader: "x-real-ip",
          now: clock.now,
        }),
      );
    }
    if (ports.instances.length > 1) proxy = await roundRobin(ports.public, ports.instances, hits);
  } catch (err) {
    // Another test process took one of the ports first: stop what started, so the caller can try new ones.
    await closeAll();
    throw err;
  }
  const binding = new PostgresBindingStore((stores[0] as PostgresStore).sql);
  return {
    base,
    ports,
    brokers,
    stores,
    binding,
    servers,
    notifier,
    skew,
    hits,
    invite: async (username, o = {}) => {
      const { invite, secret } = await createInvite(binding, { username, address: `alp:${username}@example.org`, display_name: `${username} (test)`, ...(o.email ? { email: o.email } : {}), days: o.days ?? 7, now: clock.now() });
      return { id: invite.id, secret };
    },
    close: async () => {
      if (proxy) await new Promise<void>((resolve) => proxy.close(() => resolve()));
      await closeAll();
    },
  };
}

// ---- browser-side steps

const post = (h: Hosted, b: Browser, path: string, form: Record<string, string | string[]>, headers: Record<string, string> = {}): Promise<Response> =>
  b.request(`${h.base}${path}`, { form, headers: { origin: h.base, ...headers } });

async function csrfOf(h: Hosted, b: Browser, path = "/web"): Promise<string> {
  return csrfFrom(await (await b.request(`${h.base}${path}`)).text());
}

/** The passkey step after the invite secret: register (first time) or confirm (later). */
async function passkeyStep(h: Hosted, b: Browser, auth: SoftAuthenticator): Promise<Response> {
  const csrf = await csrfOf(h, b, "/web/passkey");
  const o = await post(h, b, "/web/passkey", { csrf, alp_webauthn: "options" });
  assert.equal(o.status, 200);
  const opts = (await o.json()) as { kind: string; publicKey: J };
  const answer = opts.kind === "create" ? auth.register(opts.publicKey) : auth.assert(opts.publicKey);
  return post(h, b, "/web/passkey", { csrf, credential: JSON.stringify(answer) });
}

async function signIn(h: Hosted, username: string, secret: string, auth: SoftAuthenticator, b = new Browser()): Promise<Browser> {
  const login = await post(h, b, "/web/login", { username, secret });
  assert.equal(login.status, 303, `sign-in as ${username}`);
  assert.equal(login.headers.get("location"), "/web/passkey");
  const done = await passkeyStep(h, b, auth);
  assert.equal(done.status, 303, "the passkey step finishes the sign-in");
  assert.equal(done.headers.get("location"), "/web");
  return b;
}

/** An action: ask for the challenge over the form's terms, answer it with the passkey, submit. */
async function approve(h: Hosted, b: Browser, auth: SoftAuthenticator, path: string, fields: Record<string, string | string[]>): Promise<Response> {
  const o = await post(h, b, path, { ...fields, alp_webauthn: "options" });
  assert.equal(o.status, 200, `options for ${path}`);
  const opts = (await o.json()) as { publicKey: J };
  return post(h, b, path, { ...fields, credential: JSON.stringify(auth.assert(opts.publicKey)) });
}

async function mintPat(h: Hosted, b: Browser, auth: SoftAuthenticator, label: string): Promise<string> {
  const res = await approve(h, b, auth, "/web/tokens", { csrf: await csrfOf(h, b), label, scopes: ["read", "send"], days: "3" });
  assert.equal(res.status, 200);
  const token = /<pre>(alpat_[A-Za-z0-9_-]{43})<\/pre>/.exec(await res.text())?.[1];
  assert.ok(token, "the token is shown once");
  return token;
}

async function rest(h: Hosted, token: string, tool: string, body: J): Promise<{ status: number; json: J }> {
  const res = await fetch(`${h.base}/rest/${tool}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as J };
}

/** The connector sign-in page: invite name and secret, then (when `auth` is given) the passkey; returns the client callback. */
async function connectorSignIn(h: Hosted, authorizationUrl: string, username: string, secret: string, auth: SoftAuthenticator | null): Promise<{ status: number; location?: string; text: string }> {
  const b = new Browser();
  const first = await b.follow(await b.request(authorizationUrl), h.base);
  const page = await first.res.text();
  assert.equal(first.res.status, 200, page.slice(0, 300));
  assert.doesNotMatch(page, /type="radio"/, "a hosted broker doesn't list who can sign in");
  const action = /<form method="post" action="([^"]+)" class="card" data-alp-passkey>/.exec(page)?.[1];
  assert.ok(action, "the sign-in form asks for the passkey");
  const target = new URL(action, h.base).href;
  const fields: Record<string, string> = { csrf: csrfFrom(page), username, secret, action: "allow" };
  if (page.includes('name="label"')) fields["label"] = "agent";
  if (!auth) {
    const r = await b.request(target, { form: fields });
    return { status: r.status, text: await r.text() };
  }
  const o = await b.request(target, { form: { ...fields, alp_webauthn: "options" } });
  if (o.status !== 200) return { status: o.status, text: await o.text() };
  const opts = (await o.json()) as { publicKey: J };
  const posted = await b.request(target, { form: { ...fields, credential: JSON.stringify(auth.assert(opts.publicKey)) } });
  const done = await b.follow(posted, h.base);
  return { status: done.res.status, ...(done.location ? { location: done.location } : {}), text: done.location ? "" : await done.res.text() };
}

// ---------------------------------------------------------------------------------------------

const external = process.env["ALP_TEST_POSTGRES_URL"];
let bridge: PgliteBridge | undefined;
let url = "";
const schemas: string[] = [];
before(async () => {
  bridge = external ? undefined : await startPgliteBridge();
  url = external ?? bridge?.url ?? "";
});
after(async () => {
  const admin = postgres(url, { max: 1, prepare: false, onnotice: () => undefined });
  for (const s of schemas) await admin.unsafe(`drop schema if exists ${s} cascade`);
  await admin.end({ timeout: 2 });
  await bridge?.close();
});
const schemaFor = (name: string): string => {
  const s = `alp_web_${name}_${process.pid}`;
  schemas.push(s);
  return s;
};

describe("hosted web view (one instance, Postgres)", () => {
  let h: Hosted;
  let ana: { secret: string; id: string };
  const anaKey = new SoftAuthenticator("");
  before(async () => {
    h = await startHosted(url, schemaFor("one"), 1);
    anaKey.origin = h.base;
    ana = await h.invite("ana", { email: "ana@example.org" });
  });
  after(async () => {
    await h?.close();
  });

  test("sign-in by invite, then a passkey before anything else; cookies and headers", async () => {
    const anon = await fetch(`${h.base}/web`);
    assert.equal(anon.status, 200);
    const csp = anon.headers.get("content-security-policy") ?? "";
    for (const d of ["default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "form-action 'self'", "base-uri 'none'", "require-trusted-types-for 'script'"]) assert.ok(csp.includes(d), d);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
    assert.equal(anon.headers.get("cross-origin-opener-policy"), "same-origin");
    assert.equal(anon.headers.get("x-frame-options"), "DENY");
    const page = await anon.text();
    assert.doesNotMatch(page, /type="radio"/, "the page doesn't list who can sign in");
    assert.match(page, /Invite-only evaluation broker/);
    assert.match(page, /<script src="\/web\/static\/passkey\.js" defer><\/script>/, "one same-origin script, no inline code");
    assert.doesNotMatch(page, /<script>/);
    const js = await fetch(`${h.base}/web/static/passkey.js`);
    assert.match(js.headers.get("content-type") ?? "", /javascript/);

    assert.equal((await post(h, new Browser(), "/web/login", { username: "ana", secret: "wrong-secret" })).status, 401);
    assert.equal((await post(h, new Browser(), "/web/login", { username: "nobody", secret: ana.secret })).status, 401);

    const b = new Browser();
    const login = await post(h, b, "/web/login", { username: "ana", secret: ana.secret });
    assert.equal(login.status, 303);
    const cookies = login.headers.getSetCookie();
    const web = cookies.find((c) => c.startsWith("__Host-alp_web="));
    assert.ok(web, "a __Host- session cookie");
    assert.match(web, /; Path=\//);
    assert.match(web, /; HttpOnly/);
    assert.match(web, /; SameSite=Strict/);
    assert.match(web, /; Secure/);
    assert.doesNotMatch(web, /Domain=|Max-Age/i, "no domain, and it ends with the browser");
    assert.ok(cookies.some((c) => /^__Host-alp_device=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict; Secure; Max-Age=31536000$/.test(c)), "a device cookie for the new-browser notice");

    // Nothing works before the passkey: not the page, not an action.
    const home = await b.request(`${h.base}/web`);
    assert.equal(home.status, 303);
    assert.equal(home.headers.get("location"), "/web/passkey");
    const early = await post(h, b, "/web/tokens", { csrf: "x", label: "early", scopes: "read", days: "1" });
    assert.equal(early.status, 303, "actions wait for the passkey too");
    assert.match(await (await b.request(`${h.base}/web/passkey`)).text(), /Create a passkey/);

    // Without user verification, the passkey isn't accepted.
    const careless = new SoftAuthenticator(h.base);
    careless.userVerified = false;
    assert.equal((await passkeyStep(h, b, careless)).status, 401);

    const before = h.notifier.sent.length;
    const done = await passkeyStep(h, b, anaKey);
    assert.equal(done.status, 303);
    assert.ok(done.headers.getSetCookie().some((c) => c.startsWith("__Host-alp_web=")), "a new session id once the sign-in completes");
    const dash = await (await b.request(`${h.base}/web`)).text();
    assert.match(dash, /ana \(test\)/);
    assert.match(dash, /New browser/);
    const notice = h.notifier.sent.slice(before).find((n) => n.kind === "new_device");
    assert.ok(notice, "a notice on sign-in from a new browser");
    assert.equal(notice.to, "ana@example.org");
    assert.equal(notice.link, `${h.base}/web`);
    assert.doesNotMatch(notice.text, /https?:\/\//, "the notice carries no link but the page's own");
    assert.equal((await h.binding.listPasskeys((await h.brokers[0]!.getPrincipal("alp:ana@example.org"))!.principal_id)).length, 1);
    assert.match(dash, /Your passkeys/);
  });

  test("a leaked invite secret used before the person's first sign-in: only the first passkey registration counts", async () => {
    const ivy = await h.invite("ivy");
    const person = new Browser();
    const thief = new Browser();
    for (const b of [person, thief]) assert.equal((await post(h, b, "/web/login", { username: "ivy", secret: ivy.secret })).status, 303);
    // Both sessions reach the passkey step; each asks for registration options.
    assert.equal((await passkeyStep(h, person, new SoftAuthenticator(h.base))).status, 303, "the first registration");
    assert.equal((await passkeyStep(h, thief, new SoftAuthenticator(h.base))).status, 401, "a second one, from another session, is refused");
    const pid = (await h.brokers[0]!.getPrincipal("alp:ivy@example.org"))!.principal_id;
    assert.equal((await h.binding.listPasskeys(pid)).length, 1);
  });

  test("every later sign-in needs the passkey; the secret alone gets nowhere; a new browser gets a notice", async () => {
    const b = new Browser();
    const login = await post(h, b, "/web/login", { username: "ana", secret: ana.secret });
    assert.equal(login.status, 303);
    assert.equal((await b.request(`${h.base}/web`)).status, 303, "the secret alone isn't a session");
    assert.match(await (await b.request(`${h.base}/web/passkey`)).text(), /Use my passkey/);
    const stranger = new SoftAuthenticator(h.base);
    assert.equal((await passkeyStep(h, b, stranger)).status, 401, "someone else's passkey doesn't sign Ana in");
    const notices = h.notifier.sent.filter((n) => n.kind === "new_device").length;
    assert.equal((await passkeyStep(h, b, anaKey)).status, 303);
    assert.equal(h.notifier.sent.filter((n) => n.kind === "new_device").length, notices + 1, "this Browser has no device cookie yet: a new browser");

    // The same browser again: no notice.
    const out = await post(h, b, "/web/logout", { csrf: await csrfOf(h, b) });
    assert.equal(out.status, 303);
    assert.equal((await b.request(`${h.base}/web`)).status, 200, "signed out: the sign-in page");
    await signIn(h, "ana", ana.secret, anaKey, b);
    assert.equal(h.notifier.sent.filter((n) => n.kind === "new_device").length, notices + 1, "a known browser: no notice");
    assert.doesNotMatch(await (await b.request(`${h.base}/web`)).text(), /New browser/);
  });

  test("every approval needs a fresh passkey assertion over exactly what the page showed", async () => {
    const b = await signIn(h, "ana", ana.secret, anaKey);
    const token = await mintPat(h, b, anaKey, "muse");
    assert.equal((await rest(h, token, "alp_whoami", {})).json["delegate"], "alp:ana@example.org/muse");

    const csrf = await csrfOf(h, b);
    const fields = { csrf, label: "second", scopes: ["read"], days: "2" };
    assert.equal((await post(h, b, "/web/tokens", fields)).status, 401, "no passkey answer: refused");

    const o = (await (await post(h, b, "/web/tokens", { ...fields, alp_webauthn: "options" })).json()) as { publicKey: J };
    const challenge = Buffer.from(String(o.publicKey["challenge"]), "base64url");
    assert.equal(challenge.length, 48, "16 random bytes, then the 32-byte hash of the terms");
    const answer = JSON.stringify(anaKey.assert(o.publicKey));
    assert.equal((await post(h, b, "/web/tokens", { ...fields, scopes: ["read", "send"], credential: answer })).status, 401, "a form changed after the challenge: refused");
    const o2 = (await (await post(h, b, "/web/tokens", { ...fields, alp_webauthn: "options" })).json()) as { publicKey: J };
    const answer2 = JSON.stringify(anaKey.assert(o2.publicKey));
    assert.equal((await post(h, b, "/web/tokens", { ...fields, credential: answer2 })).status, 200);
    assert.equal((await post(h, b, "/web/tokens", { ...fields, credential: answer2 })).status, 401, "a challenge works once");

    // Terms that change between the page and the approval: an agent-filed request settled meanwhile.
    const filed = await rest(h, token, "alp_request_connection", { to: "mallory@outside.example", scopes: ["alp.availability/1"], purpose: "scheduling" });
    assert.equal(filed.json["status"], "pending_principal");
    const id = String(filed.json["request_id"]);
    const approveFields = { csrf, scopes: ["alp.availability/1"] };
    const pending = (await (await post(h, b, `/web/connections/${id}/approve`, { ...approveFields, alp_webauthn: "options" })).json()) as { publicKey: J };
    const discard = await approve(h, b, anaKey, `/web/connections/${id}/decline`, { csrf });
    assert.equal(discard.status, 303);
    const late = await post(h, b, `/web/connections/${id}/approve`, { ...approveFields, credential: JSON.stringify(anaKey.assert(pending.publicKey)) });
    assert.equal(late.status, 401, "the terms changed after the page: the old approval doesn't apply");

    // A grant change and a disconnection need it too.
    const page = await (await b.request(`${h.base}/web`)).text();
    const tokenId = /action="\/web\/tokens\/([0-9A-Z]{26})\/revoke"/.exec(page)?.[1];
    assert.ok(tokenId);
    assert.equal((await post(h, b, `/web/tokens/${tokenId}/revoke`, { csrf })).status, 401);
    assert.equal((await approve(h, b, anaKey, `/web/tokens/${tokenId}/revoke`, { csrf })).status, 303);
    assert.equal((await approve(h, b, anaKey, "/web/delegates/revoke", { csrf, delegate: "alp:ana@example.org/muse" })).status, 303);
    assert.equal((await rest(h, token, "alp_whoami", {})).status, 401, "disconnected");
  });

  test("ratification: each person approves the agreed terms with a passkey; the record says webauthn-uv", async () => {
    const lee = await h.invite("lee");
    const leeKey = new SoftAuthenticator(h.base);
    const meeting: ScopeTerms = {
      may: ["request", "propose", "counter", "accept", "commit", "inform", "decline", "ack"],
      disclose: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
      receive: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
      commit: "ask_me",
      redaction: "reject",
    };
    const ab = await signIn(h, "ana", ana.secret, anaKey);
    const lb = await signIn(h, "lee", lee.secret, leeKey);
    const broker = h.brokers[0]!;
    const fresh = (p: string): HumanCaller => ({ kind: "human", principal: p, auth: { method: "webauthn-uv", at: new Date().toISOString() } });
    await broker.setGrant(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org", scopes: { "alp.meeting/1": meeting } });
    await broker.setGrant(fresh("alp:lee@example.org"), { counterparty: "alp:ana@example.org", scopes: { "alp.meeting/1": meeting } });
    const anaPat = await mintPat(h, ab, anaKey, "planner");
    const leePat = await mintPat(h, lb, leeKey, "assistant");
    const slot = { start: "2026-11-10T15:00:00Z", end: "2026-11-10T15:30:00Z" };
    const req = await rest(h, anaPat, "alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "request", body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-10T14:00:00Z", end: "2026-11-10T18:00:00Z" } } });
    assert.equal(req.status, 200, JSON.stringify(req.json));
    const thread = String(req.json["thread"]);
    const prop = await rest(h, leePat, "alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "propose", thread, in_reply_to: req.json["id"], body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } });
    assert.equal(prop.status, 200, JSON.stringify(prop.json));
    const terms = { title: "Launch sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
    const acc = await rest(h, anaPat, "alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "accept", thread, in_reply_to: prop.json["id"], body: { terms } });
    assert.equal(acc.status, 200, JSON.stringify(acc.json));
    for (const [b, key] of [[ab, anaKey], [lb, leeKey]] as const) {
      const home = await (await b.request(`${h.base}/web`)).text();
      const rid = /href="\/web\/ratifications\/([^"]+)"/.exec(home)?.[1];
      assert.ok(rid);
      const page = await (await b.request(`${h.base}/web/ratifications/${rid}`)).text();
      assert.match(page, /Launch sync/);
      assert.match(page, /data-alp-passkey/);
      assert.equal((await post(h, b, `/web/ratifications/${rid}/approve`, { csrf: csrfFrom(page) })).status, 401, "no passkey, no ratification");
      assert.equal((await approve(h, b, key, `/web/ratifications/${rid}/approve`, { csrf: csrfFrom(page) })).status, 303);
    }
    const commit = await rest(h, leePat, "alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.json["id"], body: { terms } });
    assert.equal(commit.status, 200, JSON.stringify(commit.json));
    const records = (await broker.listRatifications(fresh("alp:lee@example.org"))).filter((r) => r.thread === thread);
    assert.equal(records[0]?.record?.method, "webauthn-uv", "the ratification record names the passkey step-up");
  });

  test("POSTs another site starts, without the CSRF token, or to another host name are refused", async () => {
    const b = await signIn(h, "ana", ana.secret, anaKey);
    const csrf = await csrfOf(h, b);
    assert.equal((await post(h, b, "/web/tokens", { csrf, label: "x", scopes: "read", days: "1" }, { origin: "https://evil.example" })).status, 403);
    assert.equal((await post(h, b, "/web/tokens", { csrf, label: "x", scopes: "read", days: "1" }, { "sec-fetch-site": "cross-site" })).status, 403);
    assert.equal((await post(h, b, "/web/tokens", { label: "x", scopes: "read", days: "1" })).status, 403, "no CSRF token");
    assert.equal((await post(h, b, "/web/logout", { csrf: "stale" })).status, 403, "signing out needs the token too");
    const wrongHost = await new Promise<number>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port: h.ports.public, path: "/web", headers: { host: "broker.attacker.example" } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      r.on("error", reject);
      r.end();
    });
    assert.equal(wrongHost, 421, "the page answers only to the broker's own address");
  });

  test("the idle timeout ends a session; revoking an invite ends its sessions; an expired invite can't sign in", async () => {
    const b = await signIn(h, "ana", ana.secret, anaKey);
    h.skew.ms = 16 * 60 * 1000;
    try {
      assert.equal((await b.request(`${h.base}/web`)).status, 200, "after 16 idle minutes: the sign-in page");
      assert.match(await (await b.request(`${h.base}/web`)).text(), /Invitation secret/);
    } finally {
      h.skew.ms = 0;
    }
    const kim = await h.invite("kim", { days: 1 });
    const kimKey = new SoftAuthenticator(h.base);
    const kb = await signIn(h, "kim", kim.secret, kimKey);
    assert.match(await (await kb.request(`${h.base}/web`)).text(), /kim \(test\)/);
    const principalIdOf = async (address: string): Promise<string | null> => (await h.brokers[0]!.getPrincipal(address))?.principal_id ?? null;
    await revokeInvite(h.binding, kim.id, new Date(), principalIdOf);
    assert.match(await (await kb.request(`${h.base}/web`)).text(), /Invitation secret/, "revoked: the open session ended");
    assert.equal((await post(h, new Browser(), "/web/login", { username: "kim", secret: kim.secret })).status, 401, "revoked: no new sign-in");
    const zed = await h.invite("zed", { days: 1 });
    h.skew.ms = 25 * 3600 * 1000;
    try {
      assert.equal((await post(h, new Browser(), "/web/login", { username: "zed", secret: zed.secret })).status, 401, "expired");
    } finally {
      h.skew.ms = 0;
    }
  });

  test("failed sign-ins pause one name from one place after 10, even with the right secret after", async () => {
    const pat = await h.invite("pat");
    for (let i = 0; i < 10; i++) assert.equal((await post(h, new Browser(), "/web/login", { username: "pat", secret: `wrong-${i}` })).status, 401);
    const paused = await post(h, new Browser(), "/web/login", { username: "pat", secret: pat.secret });
    assert.equal(paused.status, 429);
    assert.match(await paused.text(), /Too many failed sign-ins/);
  });

  test("failed sign-ins count an IPv6 source by its /64: ten from one /64 pause that name from every address in it", async () => {
    const quinn = await h.invite("quinn");
    const from = (source: string, secret: string): Promise<Response> => post(h, new Browser(), "/web/login", { username: "quinn", secret }, { "x-real-ip": source });
    for (let i = 1; i <= 10; i++) assert.equal((await from(`2001:db8:a:1::${i.toString(16)}`, `wrong-${i}`)).status, 401);
    const paused = await from("2001:db8:a:1:ffff:ffff:ffff:ffff", quinn.secret);
    assert.equal(paused.status, 429, "another address in the same /64");
    assert.match(await paused.text(), /Too many failed sign-ins/);
    assert.notEqual((await from("2001:db8:a:2::1", quinn.secret)).status, 429, "another /64 isn't paused");
  });

  test("the connector sign-in asks for the person's passkey, over a challenge bound to that authorization", async () => {
    const oauth = new TestOAuthClient({ name: "Hosted agent" });
    const mcp = new URL(`${h.base}/mcp`);
    const first = new StreamableHTTPClientTransport(mcp, { authProvider: oauth });
    await assert.rejects(new Client({ name: "h", version: "1" }).connect(first));
    const authUrl = oauth.lastAuthorizationUrl?.href ?? "";
    const noKey = await connectorSignIn(h, authUrl, "ana", ana.secret, null);
    assert.equal(noKey.status, 200);
    assert.match(noKey.text, /passkey check didn(&#39;|')t work/, "the secret alone doesn't connect an agent");
    assert.match(noKey.text, /Invite-only evaluation broker/);
    assert.doesNotMatch(noKey.text, /Test identities only/);
    const wrongKey = await connectorSignIn(h, authUrl, "ana", ana.secret, new SoftAuthenticator(h.base));
    assert.ok(!wrongKey.location, "someone else's passkey doesn't connect an agent");
    const quinn = await h.invite("quinn");
    const noPasskeyYet = await connectorSignIn(h, authUrl, "quinn", quinn.secret, new SoftAuthenticator(h.base));
    assert.equal(noPasskeyYet.status, 403);
    assert.match(noPasskeyYet.text, /create a passkey/);
    const ok = await connectorSignIn(h, authUrl, "ana", ana.secret, anaKey);
    assert.ok(ok.location, ok.text.slice(0, 300));
    const callback = new URL(ok.location ?? "");
    assert.equal(callback.searchParams.get("iss"), h.base);
    await first.finishAuth(callback.searchParams);
    const client = new Client({ name: "h", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StreamableHTTPClientTransport(mcp, { authProvider: oauth }));
    const who = (await client.callTool({ name: "alp_whoami", arguments: {} })) as CallToolResult;
    assert.equal((who.structuredContent as J)["address"], "alp:ana@example.org");
    await client.close();
  });
});

describe("hosted: POSTs per address are limited", () => {
  let h: Hosted;
  before(async () => {
    h = await startHosted(url, schemaFor("limits"), 1, { postsPerMinute: 3 });
  });
  after(async () => {
    await h?.close();
  });

  test("past the limit, 429 with Retry-After", async () => {
    const answers: Response[] = [];
    for (let i = 0; i < 4; i++) answers.push(await post(h, new Browser(), "/web/login", { username: "ana", secret: "wrong" }));
    assert.deepEqual(answers.map((r) => r.status), [401, 401, 401, 429]);
    assert.equal(answers[3]?.headers.get("retry-after"), "60");
  });
});

describe("hosted: two instances behind one address share Postgres", () => {
  let h: Hosted;
  let ana: { secret: string; id: string };
  const key = new SoftAuthenticator("");
  before(async () => {
    h = await startHosted(url, schemaFor("two"), 2);
    key.origin = h.base;
    ana = await h.invite("ana");
  });
  after(async () => {
    await h?.close();
  });

  test("sessions, challenges, tokens, limits and refresh-token reuse hold across instances", async () => {
    // The web view: each request of the sign-in and approval goes to the other instance.
    const b = await signIn(h, "ana", ana.secret, key);
    const pat = await mintPat(h, b, key, "muse");
    for (let i = 0; i < 4; i++) assert.equal((await rest(h, pat, "alp_whoami", {})).status, 200);

    // OAuth: registration, sign-in, code and token exchange on whichever instance answers.
    const oauth = new TestOAuthClient({ name: "Fleet agent" });
    const mcp = new URL(`${h.base}/mcp`);
    const first = new StreamableHTTPClientTransport(mcp, { authProvider: oauth });
    await assert.rejects(new Client({ name: "f", version: "1" }).connect(first));
    const ok = await connectorSignIn(h, oauth.lastAuthorizationUrl?.href ?? "", "ana", ana.secret, key);
    assert.ok(ok.location, ok.text.slice(0, 300));
    await first.finishAuth(new URL(ok.location ?? "").searchParams);
    const tokens = oauth.tokens();
    assert.ok(tokens?.refresh_token);
    for (let i = 0; i < 2; i++) {
      const call = await fetch(mcp, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tokens.access_token}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      assert.equal(call.status, 200, "the access token works on both instances");
    }
    const as = (await (await fetch(`${h.base}/.well-known/oauth-authorization-server`)).json()) as J;
    const metadata = as as Parameters<typeof refreshAuthorization>[1]["metadata"];
    const info = oauth.clientInformation();
    assert.ok(info);
    const refresh = (rt: string) => refreshAuthorization(h.base, { metadata, clientInformation: info, refreshToken: rt, resource: mcp });
    const [r1, r2] = await Promise.all([refresh(tokens.refresh_token), refresh(tokens.refresh_token)]);
    assert.ok(r1.access_token && r2.access_token, "two overlapping refreshes, on two instances, both work");
    // Past the overlap interval, the rotated token is theft wherever it's presented: the connection ends.
    await h.stores[0]!.sql`update oauth_artifacts set payload = jsonb_set(payload, '{consumed}', to_jsonb(extract(epoch from now())::bigint - 120)) where model = 'RefreshToken' and payload ? 'consumed'`;
    await assert.rejects(refresh(tokens.refresh_token), /invalid_grant|grant request is invalid/i);
    for (let i = 0; i < 2; i++) {
      const dead = await fetch(mcp, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${r1.access_token}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      assert.equal(dead.status, 401, "revoked on every instance at once");
    }

    // One failed-sign-in window across instances: 10 failures, split between them, pause the name.
    const zoe = await h.invite("zoe");
    for (let i = 0; i < 10; i++) assert.equal((await post(h, new Browser(), "/web/login", { username: "zoe", secret: `wrong-${i}` })).status, 401);
    assert.equal((await post(h, new Browser(), "/web/login", { username: "zoe", secret: zoe.secret })).status, 429);

    const [one = 0, two = 0] = h.ports.instances;
    assert.ok((h.hits.get(one) ?? 0) > 10 && (h.hits.get(two) ?? 0) > 10, `both instances served (${[...h.hits.entries()].join(" ")})`);
  });
});
