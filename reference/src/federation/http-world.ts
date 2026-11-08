// SPDX-License-Identifier: FSL-1.1-ALv2
// A small fictional world over real localhost HTTP, shared by the federation tests and `npm run demo:federation`:
//  - example.org's domain authority lists broker-a (Ana's provider broker, by explicit list) and broker-b
//    (every other example.org address, including Lee);
//  - broker-c is a rogue broker that registers its own "ana@example.org"; no document names it. It also claims
//    nowhere.example, a domain that publishes no document at all;
//  - outside.example has its own domain authority and broker (Mallory, an outsider with a legitimate broker).
// Every published origin is an RFC 2606 name that the dev host map points at a loopback port. Each broker has its
// own resolver (its own cache), its own HTTPS transport and its own federation server. One ManualClock drives every
// broker and resolver, so tests can move past a document's max_age. Names and data are fictional.

import { Broker } from "../core/broker.ts";
import { ManualClock } from "../core/clock.ts";
import { DEV_ISSUER } from "../core/identity.ts";
import { KeyRing } from "../core/keys.ts";
import { RecordingNotifier } from "../core/notify.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { ScopeRegistry } from "../core/scopes/index.ts";
import { MemorySecurityEvents } from "../core/security-events.ts";
import type { BrokerEntry, DelegateCaller, DomainDocument, OrgPolicy } from "../core/types.ts";
import { ANA, CLIENTS, LEE, MALLORY, examplePolicy } from "../demo/world.ts";
import type { Person } from "../demo/world.ts";
import { MemoryStore } from "../storage/memory.ts";
import { FEDERATION_PATHS, brokerEntry, buildDomainDocument } from "./domain-authority.ts";
import { HardenedFetcher } from "./fetcher.ts";
import type { RequestSignatureMode } from "./inbox.ts";
import type { DevHostMap } from "./net-guard.ts";
import { HttpsDomainResolver, StaticTxtLookup } from "./resolver.ts";
import { DomainAuthorityServer, FederationServer, assertPortsFree } from "./server.ts";
import type { FederationServerOptions, WireRecord } from "./server.ts";
import { HttpsFederationTransport } from "./transport.ts";
import type { DeliveryAttempt, RetryPolicy } from "./transport.ts";

export const FED_IDS = {
  a: "https://broker-a.example",
  b: "https://broker-b.example",
  c: "https://broker-c.example",
  outside: "https://broker.outside.example",
} as const;

export type NodeName = keyof typeof FED_IDS;

/** Port layout from a base port: 6 consecutive ports. */
export const PORT_OFFSETS = { exampleAuthority: 0, outsideAuthority: 1, a: 2, b: 3, c: 4, outside: 5 } as const;
export const WORLD_PORT_COUNT = 6;

export interface HttpNode {
  id: string;
  port: number;
  broker: Broker;
  server: FederationServer;
  resolver: HttpsDomainResolver;
  transport: HttpsFederationTransport;
  httpKeys: KeyRing | undefined;
}

export interface HttpWorld {
  clock: ManualClock;
  ports: Record<keyof typeof PORT_OFFSETS, number>;
  devHosts: DevHostMap;
  /** A fetcher with the same dev host map, for tests that post raw requests. */
  fetcher: HardenedFetcher;
  txt: StaticTxtLookup;
  notifier: RecordingNotifier;
  events: MemorySecurityEvents;
  exampleAuthority: DomainAuthorityServer;
  outsideAuthority: DomainAuthorityServer;
  a: HttpNode;
  b: HttpNode;
  c: HttpNode;
  outside: HttpNode;
  ana: Person;
  lee: Person;
  mallory: Person;
  /** The rogue broker's own agent "for" ana@example.org. */
  rogueAna: DelegateCaller;
  /** The entry example.org publishes for a node (its keys pinned). */
  entry(node: NodeName, principals: BrokerEntry["principals"]): BrokerEntry;
  /** Publish example.org's document again with the next serial. Default: broker-a for Ana, broker-b for everyone else. */
  publishExample(change?: { brokers?: BrokerEntry[]; revoked?: { jkt: string; compromised_since: string }[]; maxAge?: number }): DomainDocument;
  /** Every request any server saw, oldest first. */
  wire(): WireRecord[];
  /** Every delivery attempt any transport made, oldest first. */
  attempts(): DeliveryAttempt[];
  close(): Promise<void>;
}

export interface HttpWorldOptions {
  basePort: number;
  /** Sign every federation POST with RFC 9421 (spec 12.2.2). Default true. */
  signRequests?: boolean;
  requestSignatures?: RequestSignatureMode;
  retry?: Partial<RetryPolicy>;
  sleep?: (ms: number) => Promise<void>;
  intercept?: Partial<Record<NodeName, FederationServerOptions["intercept"]>>;
  /** Print notifications as the email or text they would be. */
  print?: (text: string) => void;
  /** example.org's max_age. Default 3600. */
  maxAge?: number;
}

const START = "2026-11-09T14:00:00.000Z";

export async function startHttpWorld(opts: HttpWorldOptions): Promise<HttpWorld> {
  const base = opts.basePort;
  const ports = {
    exampleAuthority: base + PORT_OFFSETS.exampleAuthority,
    outsideAuthority: base + PORT_OFFSETS.outsideAuthority,
    a: base + PORT_OFFSETS.a,
    b: base + PORT_OFFSETS.b,
    c: base + PORT_OFFSETS.c,
    outside: base + PORT_OFFSETS.outside,
  };
  await assertPortsFree(Object.values(ports));
  const loop = (port: number): string => `http://127.0.0.1:${port}`;
  const devHosts: DevHostMap = {
    "https://example.org": loop(ports.exampleAuthority),
    [`https://${PROTOCOL.hostLabel}.example.org`]: loop(ports.exampleAuthority),
    "https://outside.example": loop(ports.outsideAuthority),
    [`https://${PROTOCOL.hostLabel}.outside.example`]: loop(ports.outsideAuthority),
    // nowhere.example publishes no document: both locations reach a server that answers 404 for that name.
    "https://nowhere.example": loop(ports.exampleAuthority),
    [`https://${PROTOCOL.hostLabel}.nowhere.example`]: loop(ports.exampleAuthority),
    [FED_IDS.a]: loop(ports.a),
    [FED_IDS.b]: loop(ports.b),
    [FED_IDS.c]: loop(ports.c),
    [FED_IDS.outside]: loop(ports.outside),
  };
  const clock = new ManualClock(START);
  const now = clock.now();
  const fetcher = new HardenedFetcher({ devHosts });
  const txt = new StaticTxtLookup();
  const notifier = new RecordingNotifier(opts.print ? { print: opts.print } : {});
  const events = new MemorySecurityEvents();
  const scopes = ScopeRegistry.load();
  const signRequests = opts.signRequests ?? true;

  const started: { close(): Promise<void> }[] = [];
  /** Every transport's attempts in the order they happened. */
  const attemptLog: DeliveryAttempt[] = [];
  const closeAll = async (): Promise<void> => {
    await Promise.allSettled(started.map((s) => s.close()));
  };

  try {
    const node = async (name: NodeName, policies: OrgPolicy[], domains: string[]): Promise<HttpNode> => {
      const id = FED_IDS[name];
      const keys = await KeyRing.generate(now);
      await keys.prepareNext(now);
      const httpKeys = signRequests ? await KeyRing.generate(now, "http") : undefined;
      const resolver = new HttpsDomainResolver({ fetcher, clock, txt });
      const transport = new HttpsFederationTransport({
        brokerId: id,
        fetcher,
        clock,
        ...(opts.retry ? { retry: opts.retry } : {}),
        ...(opts.sleep ? { sleep: opts.sleep } : {}),
        ...(httpKeys ? { requestSigningKeys: httpKeys } : {}),
        onAttempt: (a) => attemptLog.push(a),
      });
      const broker = new Broker({ id, store: new MemoryStore(), keys, resolver, transport, notifier, securityEvents: events, clock, scopes, policies, domains });
      const intercept = opts.intercept?.[name];
      const server = new FederationServer({
        broker,
        inboxUrl: `${id}${FEDERATION_PATHS.inbox}`,
        jwksUrl: `${id}${FEDERATION_PATHS.jwks}`,
        ...(httpKeys ? { extraKeys: () => httpKeys.jwks() } : {}),
        resolver,
        requestSignatures: opts.requestSignatures ?? "verify",
        clock,
        ...(intercept ? { intercept } : {}),
      });
      await server.listen(ports[name]);
      started.push(server);
      return { id, port: ports[name], broker, server, resolver, transport, httpKeys };
    };

    // broker-a and broker-b are both authorized by example.org, so both enforce its (private) policy.
    const a = await node("a", [examplePolicy(now)], ["example.org"]);
    const b = await node("b", [examplePolicy(now)], ["example.org"]);
    // The rogue also claims nowhere.example, a domain that publishes no document.
    const c = await node("c", [], ["example.org", "nowhere.example"]);
    const outside = await node("outside", [], ["outside.example"]);
    const nodes: Record<NodeName, HttpNode> = { a, b, c, outside };

    const entry = (name: NodeName, principals: BrokerEntry["principals"]): BrokerEntry => {
      const n = nodes[name];
      return brokerEntry({ id: n.id, keys: n.httpKeys ? [n.broker.keys, n.httpKeys] : [n.broker.keys], principals, mcp: `${n.id}/mcp` });
    };

    const exampleAuthority = new DomainAuthorityServer("example.org");
    const outsideAuthority = new DomainAuthorityServer("outside.example");
    await exampleAuthority.listen(ports.exampleAuthority);
    started.push(exampleAuthority);
    await outsideAuthority.listen(ports.outsideAuthority);
    started.push(outsideAuthority);

    let exampleSerial = 0;
    const publishExample = (change: { brokers?: BrokerEntry[]; revoked?: { jkt: string; compromised_since: string }[]; maxAge?: number } = {}): DomainDocument => {
      exampleSerial++;
      return exampleAuthority.publish(
        buildDomainDocument({
          domain: "example.org",
          serial: exampleSerial,
          maxAge: change.maxAge ?? opts.maxAge ?? 3600,
          brokers: change.brokers ?? [entry("a", [ANA]), entry("b", "*")],
          ...(change.revoked ? { revoked: change.revoked } : {}),
          updatedAt: clock.now(),
        }),
      );
    };
    publishExample();
    outsideAuthority.publish(buildDomainDocument({ domain: "outside.example", serial: 1, brokers: [entry("outside", "*")], updatedAt: now }));

    const person = async (n: HttpNode, address: string, label: string, name: string): Promise<Person> => {
      await n.broker.registerPrincipal({ address, identity: { iss: DEV_ISSUER, sub: `dev-${name.toLowerCase()}` }, display_name: name, contact: { email: address.slice(address.indexOf(":") + 1) } });
      const d = await n.broker.registerDelegate({ principal: address, label, kind: "bridged", client_id: CLIENTS.connector });
      return {
        address,
        agent: { kind: "delegate", principal: address, delegate: d.id, client_id: CLIENTS.connector },
        human: () => ({ kind: "human", principal: address, auth: { method: "reauth-dev", at: clock.now().toISOString() } }),
      };
    };
    const ana = await person(a, ANA, "muse", "Ana");
    const lee = await person(b, LEE, "dot", "Lee");
    const mallory = await person(outside, MALLORY, "agent", "Mallory");
    // The rogue broker registers its own "ana@example.org", with a grant for Lee, so it will sign and send.
    await c.broker.registerPrincipal({ address: ANA, identity: { iss: FED_IDS.c, sub: "ana" }, display_name: "Ana (forged)" });
    const rogueDelegate = await c.broker.registerDelegate({ principal: ANA, label: "muse", client_id: CLIENTS.connector });
    await c.broker.setGrant(
      { kind: "human", principal: ANA, auth: { method: "reauth-dev", at: now.toISOString() } },
      { counterparty: LEE, scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/questions/*", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } } },
    );

    return {
      clock,
      ports,
      devHosts,
      fetcher,
      txt,
      notifier,
      events,
      exampleAuthority,
      outsideAuthority,
      a,
      b,
      c,
      outside,
      ana,
      lee,
      mallory,
      rogueAna: { kind: "delegate", principal: ANA, delegate: rogueDelegate.id, client_id: CLIENTS.connector },
      entry,
      publishExample,
      wire: () =>
        [exampleAuthority.requests, outsideAuthority.requests, ...Object.values(nodes).map((n) => n.server.requests)]
          .flat()
          .sort((x, y) => x.at.localeCompare(y.at)),
      attempts: () => [...attemptLog],
      close: closeAll,
    };
  } catch (err) {
    await closeAll();
    throw err;
  }
}
