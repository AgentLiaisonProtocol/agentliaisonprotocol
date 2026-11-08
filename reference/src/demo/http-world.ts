// SPDX-License-Identifier: FSL-1.1-ALv2
// The demo's world over real HTTP on 127.0.0.1 (`npm run demo`). Fictional names and data only.
//  - example.org's domain authority, at first naming two hosted brokers (the Hosted Broker profile, spec 13.5):
//    broker-a (home for Ana and Fran) and broker-b (home for everyone else at example.org, Lee included). example.org
//    chose them and gave them its private policy; neither is an agent vendor's broker;
//  - broker-c, a rogue broker no document names;
//  - outside.example's authority and its own broker (Mallory, an unwanted outsider, and Rio, a partner, both on a
//    legitimate broker);
//  - broker.example.org, the organization's own broker (organization-hosted profile), started for step 7.
// Lee also has three agents of his own on broker-b (step 0, spec 6.14): a company dot that connects with a client
// broker-b issued only to example.org's workspace, a company Claude whose vendor publishes a client identity for
// example.org's organization only and which signs its token requests with that organization's key, and a personal
// Muse that uses a personal access token.
// Every broker runs the same code: the core, the client binding (MCP, REST, OAuth 2.1 authorization server and the
// connector sign-in page) on its public port, the federation inbox and JWKS on the same origin, and the person's web
// view on a loopback port of its own. Each fictional https name is sent to its 127.0.0.1 port by the development host
// map, for the brokers' federation fetcher and for the agents' own HTTP clients alike.

import { randomBytes } from "node:crypto";
import { Broker } from "../core/broker.ts";
import { systemClock } from "../core/clock.ts";
import { DEV_ISSUER, DevIdentityVerifier } from "../core/identity.ts";
import type { DevIdentity } from "../core/identity.ts";
import type { Notifier } from "../core/interfaces.ts";
import { KeyRing } from "../core/keys.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { ScopeRegistry } from "../core/scopes/index.ts";
import { MemorySecurityEvents } from "../core/security-events.ts";
import type { BrokerEntry, DomainDocument, OrgPolicy } from "../core/types.ts";
import { FEDERATION_PATHS, brokerEntry, buildDomainDocument } from "../federation/domain-authority.ts";
import { HardenedFetcher } from "../federation/fetcher.ts";
import type { DevHostMap } from "../federation/net-guard.ts";
import { HttpsDomainResolver } from "../federation/resolver.ts";
import { DomainAuthorityServer, FederationServer, assertPortsFree } from "../federation/server.ts";
import type { WireRecord } from "../federation/server.ts";
import { HttpsFederationTransport } from "../federation/transport.ts";
import type { DeliveryAttempt } from "../federation/transport.ts";
import { startBrokerServer } from "../server.ts";
import type { RunningBrokerServer } from "../server.ts";
import { MemoryStore } from "../storage/memory.ts";
import { DEMO_PORT_BASE } from "../test-ports.ts";
import { examplePolicy } from "./world.ts";

export const DEMO_BASE_PORT = DEMO_PORT_BASE;
export const DEMO_PORT_COUNT = 11;

export const ORIGINS = {
  a: "https://broker-a.example",
  b: "https://broker-b.example",
  c: "https://broker-c.example",
  outside: "https://broker.outside.example",
  org: "https://broker.example.org",
} as const;

/** The agents' vendors publish client ID metadata documents (served from memory in the demo). */
export const VENDOR_CLIENTS = {
  a: "https://agent-a.example/oauth/client.json",
  b: "https://agent-b.example/oauth/client.json",
  /** A vendor example.org's allow-list doesn't name. */
  x: "https://agent-x.example/oauth/client.json",
  /**
   * Lee's company Claude: a client identity its vendor publishes for example.org's organization only, authenticating at
   * the token endpoint with a key held for that organization (private_key_jwt), as spec 5.4 requires for `tenant`.
   */
  claude: "https://agent-c.example/orgs/example-org/oauth/client.json",
  /** The public client identity of the dot's product, shared by every personal account of it. */
  personal: "https://agent-d.example/oauth/client.json",
} as const;
/** Lee's company dot: a client broker-b's operator registered for example.org's workspace only (with a secret). */
export const DOT_CLIENT_ID = "example-org-workspace-dot";
export const REDIRECT = "http://127.0.0.1:47199/callback";

export const PEOPLE = {
  ana: { username: "ana", address: "alp:ana@example.org", display_name: "Ana (analyst)" },
  fran: { username: "fran", address: "alp:fran@example.org", display_name: "Fran (analyst)" },
  lee: { username: "lee", address: "alp:lee@example.org", display_name: "Lee (leader)" },
  kim: { username: "kim", address: "alp:kim@example.org", display_name: "Kim (planner)" },
  mallory: { username: "mallory", address: "alp:mallory@outside.example", display_name: "Mallory (outsider)" },
  rio: { username: "rio", address: "alp:rio@outside.example", display_name: "Rio (a partner)" },
} as const satisfies Record<string, DevIdentity>;

const CORE_SCOPES = ["alp.briefing/1", "alp.availability/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"];

/**
 * example.org's private policy (never published): the demo world's, with its agents on the `clients` allow-list
 * (enforce mode) and meetings between staff allowed by default. Each listed client gets the attestation and class the
 * organization records for it (spec 5.4): the two vendors' agents, Lee's company dot (org-client: a credential issued
 * only to the company workspace), his company Claude (tenant: a client identity for this organization only), personal
 * access tokens (self, consumer) and the dot's product on a personal account (its vendor-wide client: consumer).
 * Fields labeled confidential go only to enterprise agents with org-client or tenant attestation; between one
 * person's own agents they are otherwise held for the person, and confidential.financial is refused (spec 6.14).
 */
export function demoPolicy(now: Date): OrgPolicy {
  const p = examplePolicy(now, {
    clients: {
      mode: "enforce",
      allowed: [
        { client_id: VENDOR_CLIENTS.a, scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: true, retention_days: 30 },
        { client_id: VENDOR_CLIENTS.b, scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: true, retention_days: 30 },
        { client_id: DOT_CLIENT_ID, label: "dot", scopes: CORE_SCOPES, attestation: "org-client", class: "enterprise", no_training: true, retention_days: 30 },
        { client_id: VENDOR_CLIENTS.claude, label: "claude", scopes: CORE_SCOPES, attestation: "tenant", class: "enterprise", no_training: true, retention_days: 30 },
        { client_id: "pat", scopes: CORE_SCOPES, attestation: "self", class: "consumer", no_training: false },
        { client_id: VENDOR_CLIENTS.personal, scopes: CORE_SCOPES, attestation: "vendor", class: "consumer", no_training: false },
      ],
    },
    groups: { finance: { members: [] } },
    inbound_default: "response_only",
    delivery_minimums: [
      { labels: ["confidential.financial"], min_class: "enterprise", min_attestation: "org-client", otherwise: "block" },
      { labels: ["confidential", "confidential.*"], min_class: "enterprise", min_attestation: "org-client", otherwise: "hold" },
    ],
  });
  p.classification = { ...(p.classification ?? {}), overrides: { "alp.status/1": { "/body/blockers": ["confidential"] } } };
  const staff = p.default_relationships?.[0];
  if (staff) {
    staff.scopes["alp.meeting/1"] = {
      forward: { may: ["propose", "counter", "accept", "commit", "decline", "inform", "ack"], fields: ["/body/title", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms/duration_minutes", "/body/terms/timezone", "/body/terms/start", "/body/terms/end", "/body/terms/location/kind"] },
      reverse: { may: ["propose", "counter", "accept", "commit", "decline", "inform", "ack"], fields: ["/body/title", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms/duration_minutes", "/body/terms/timezone", "/body/terms/start", "/body/terms/end", "/body/terms/location/kind"] },
      commit: "ask_me",
    };
  }
  return p;
}

export function vendorDocument(clientId: string, name: string, jwksUri?: string): Record<string, unknown> {
  return {
    client_id: clientId,
    client_name: name,
    redirect_uris: [REDIRECT],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    ...(jwksUri ? { token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: "ES256", jwks_uri: jwksUri } : { token_endpoint_auth_method: "none" }),
  };
}

/** Where the company Claude's vendor publishes the public key of example.org's organization client. */
export const CLAUDE_ORG_JWKS = "https://agent-c.example/orgs/example-org/oauth/jwks.json";

export interface DemoNode {
  name: string;
  id: string;
  broker: Broker;
  keys: KeyRing;
  httpKeys: KeyRing;
  resolver: HttpsDomainResolver;
  federation: FederationServer;
  server?: RunningBrokerServer;
  publicPort: number;
  webPort?: number;
  /** http://127.0.0.1:<webPort> */
  web?: string;
}

export interface DemoWorld {
  ports: number[];
  devHosts: DevHostMap;
  fetcher: HardenedFetcher;
  secret: string;
  /** The client secret broker-b issued to example.org's workspace for the company dot (generated per run; test only). */
  dotSecret: string;
  notifier: Notifier;
  events: MemorySecurityEvents;
  exampleAuthority: DomainAuthorityServer;
  outsideAuthority: DomainAuthorityServer;
  a: DemoNode;
  b: DemoNode;
  c: DemoNode;
  outside: DemoNode;
  org?: DemoNode;
  attempts: DeliveryAttempt[];
  /** Publish example.org's document again (next serial). */
  publishExample(brokers: BrokerEntry[]): DomainDocument;
  entry(node: DemoNode, principals: BrokerEntry["principals"]): BrokerEntry;
  /** Start example.org's own broker (organization-hosted) on its ports. */
  startOrg(): Promise<DemoNode>;
  wire(): WireRecord[];
  close(): Promise<void>;
}

/** Route every request for a demo origin to its loopback port, for the agents' HTTP clients (fetch). */
export function installHostMap(devHosts: DevHostMap): () => void {
  const real = globalThis.fetch;
  const mapped = (raw: string): string | null => {
    const u = new URL(raw);
    const target = devHosts[u.origin];
    return target ? `${target}${u.pathname}${u.search}` : null;
  };
  // The response keeps the URL the client asked for, so relative redirects resolve against the public name.
  const keepUrl = (res: Response, url: string): Response => Object.defineProperty(res, "url", { value: url, configurable: true });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    if (input instanceof Request) {
      const to = mapped(input.url);
      return to ? keepUrl(await real(new Request(to, input), init), input.url) : real(input, init);
    }
    const asked = input instanceof URL ? input.href : input;
    const to = mapped(asked);
    return to ? keepUrl(await real(to, init), asked) : real(input, init);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

export async function startDemoWorld(opts: { notifier: Notifier; basePort?: number; vendorDocs: Record<string, Record<string, unknown>> }): Promise<DemoWorld> {
  const base = opts.basePort ?? DEMO_BASE_PORT;
  const ports = Array.from({ length: DEMO_PORT_COUNT }, (_, i) => base + i);
  await assertPortsFree(ports);
  const port = { exampleAuthority: base, outsideAuthority: base + 1, a: base + 2, aWeb: base + 3, b: base + 4, bWeb: base + 5, c: base + 6, outside: base + 7, outsideWeb: base + 8, org: base + 9, orgWeb: base + 10 };
  const loop = (p: number): string => `http://127.0.0.1:${p}`;
  const devHosts: DevHostMap = {
    "https://example.org": loop(port.exampleAuthority),
    [`https://${PROTOCOL.hostLabel}.example.org`]: loop(port.exampleAuthority),
    "https://outside.example": loop(port.outsideAuthority),
    [`https://${PROTOCOL.hostLabel}.outside.example`]: loop(port.outsideAuthority),
    [ORIGINS.a]: loop(port.a),
    [ORIGINS.b]: loop(port.b),
    [ORIGINS.c]: loop(port.c),
    [ORIGINS.outside]: loop(port.outside),
    [ORIGINS.org]: loop(port.org),
  };
  const clock = systemClock;
  const now = clock.now();
  const fetcher = new HardenedFetcher({ devHosts });
  const events = new MemorySecurityEvents();
  const scopes = ScopeRegistry.load();
  const secret = randomBytes(18).toString("base64url");
  const dotSecret = randomBytes(24).toString("base64url");
  const dotClient = { client_id: DOT_CLIENT_ID, client_secret: dotSecret, client_name: "Company dot (example.org workspace)", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "client_secret_basic" };
  const attempts: DeliveryAttempt[] = [];
  const started: { close(): Promise<void> }[] = [];
  const closeAll = async (): Promise<void> => {
    for (const s of [...started].reverse()) await s.close().catch(() => undefined);
  };
  // The authorization servers fetch client ID metadata documents from the vendors' sites; here, from memory.
  const vendorFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const doc = opts.vendorDocs[url];
    if (doc) return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json", "cache-control": "max-age=60" } });
    return new Response("not found", { status: 404 });
  };

  const node = async (name: string, id: string, publicPort: number, webPort: number | undefined, domains: string[], policies: OrgPolicy[], people: DevIdentity[], staticClients: { client_id: string }[] = []): Promise<DemoNode> => {
    const keys = await KeyRing.generate(now);
    await keys.prepareNext(now);
    const httpKeys = await KeyRing.generate(now, "http");
    const resolver = new HttpsDomainResolver({ fetcher, clock });
    const transport = new HttpsFederationTransport({ brokerId: id, fetcher, clock, requestSigningKeys: httpKeys, onAttempt: (a) => attempts.push(a) });
    const broker = new Broker({ id, store: new MemoryStore(), keys, resolver, transport, notifier: opts.notifier, securityEvents: events, clock, scopes, policies, domains, ...(webPort ? { webBaseUrl: `${loop(webPort)}/web` } : {}) });
    // People are known to their broker before they connect anything (their IdP account), with a contact address.
    for (const p of people) {
      await broker.registerPrincipal({ address: p.address, identity: { iss: DEV_ISSUER, sub: `dev-${p.username}` }, ...(p.display_name ? { display_name: p.display_name } : {}), contact: { email: p.address.slice(p.address.indexOf(":") + 1) } });
    }
    const federation = new FederationServer({ broker, inboxUrl: `${id}${FEDERATION_PATHS.inbox}`, jwksUrl: `${id}${FEDERATION_PATHS.jwks}`, extraKeys: () => httpKeys.jwks(), resolver, requestSignatures: "verify", clock });
    const n: DemoNode = { name, id, broker, keys, httpKeys, resolver, federation, publicPort, ...(webPort ? { webPort, web: loop(webPort) } : {}) };
    if (people.length) {
      const server = await startBrokerServer({
        broker,
        publicUrl: id,
        port: publicPort,
        ...(webPort ? { webPort } : {}),
        identity: new DevIdentityVerifier(people, { secret }),
        idpMode: "dev",
        requireSecret: true,
        policies: () => policies,
        notifier: opts.notifier,
        redirectHosts: [],
        fetch: vendorFetch,
        rawRoutes: [federation.handler()],
        ...(staticClients.length ? { staticClients } : {}),
      });
      started.push(server);
      n.server = server;
    } else {
      await federation.listen(publicPort);
      started.push(federation);
    }
    return n;
  };

  try {
    const policy = demoPolicy(now);
    const a = await node("broker-a", ORIGINS.a, port.a, port.aWeb, ["example.org"], [policy], [PEOPLE.ana, PEOPLE.fran]);
    const b = await node("broker-b", ORIGINS.b, port.b, port.bWeb, ["example.org"], [policy], [PEOPLE.lee], [dotClient]);
    // The rogue: it registers its own "ana@example.org" and signs as her, but no document names it.
    const c = await node("broker-c", ORIGINS.c, port.c, undefined, ["example.org"], [], []);
    await c.broker.registerPrincipal({ address: PEOPLE.ana.address, identity: { iss: ORIGINS.c, sub: "ana" }, display_name: "Ana (forged)" });
    const outside = await node("outside.example's broker", ORIGINS.outside, port.outside, port.outsideWeb, ["outside.example"], [], [PEOPLE.mallory, PEOPLE.rio]);

    const exampleAuthority = new DomainAuthorityServer("example.org");
    const outsideAuthority = new DomainAuthorityServer("outside.example");
    await exampleAuthority.listen(port.exampleAuthority);
    started.push(exampleAuthority);
    await outsideAuthority.listen(port.outsideAuthority);
    started.push(outsideAuthority);

    const entry = (n: DemoNode, principals: BrokerEntry["principals"]): BrokerEntry => brokerEntry({ id: n.id, keys: [n.keys, n.httpKeys], principals, ...(n.server ? { mcp: `${n.id}/mcp`, rest: `${n.id}/rest` } : {}) });
    let serial = 0;
    const publishExample = (brokers: BrokerEntry[]): DomainDocument => exampleAuthority.publish(buildDomainDocument({ domain: "example.org", serial: ++serial, brokers, updatedAt: clock.now() }));
    publishExample([entry(a, [PEOPLE.ana.address, PEOPLE.fran.address]), entry(b, "*")]);
    outsideAuthority.publish(buildDomainDocument({ domain: "outside.example", serial: 1, brokers: [entry(outside, "*")], updatedAt: now }));

    const w: DemoWorld = {
      ports,
      devHosts,
      fetcher,
      secret,
      dotSecret,
      notifier: opts.notifier,
      events,
      exampleAuthority,
      outsideAuthority,
      a,
      b,
      c,
      outside,
      attempts,
      publishExample,
      entry,
      startOrg: async () => {
        const org = await node("broker.example.org", ORIGINS.org, port.org, port.orgWeb, ["example.org"], [demoPolicy(clock.now())], [PEOPLE.ana, PEOPLE.fran, PEOPLE.lee, PEOPLE.kim]);
        w.org = org;
        return org;
      },
      wire: () => [exampleAuthority.requests, outsideAuthority.requests, ...[a, b, c, outside, ...(w.org ? [w.org] : [])].map((n) => n.federation.requests)].flat().sort((x, y) => x.at.localeCompare(y.at)),
      close: closeAll,
    };
    return w;
  } catch (err) {
    await closeAll();
    throw err;
  }
}
