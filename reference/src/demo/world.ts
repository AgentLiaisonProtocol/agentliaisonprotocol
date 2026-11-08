// SPDX-License-Identifier: FSL-1.1-ALv2
// A small fictional world on the in-process federation, shared by the core tests and the demo:
//  - example.org runs a Local broker for Ana, Lee and Fran (the in-organization case; private org policy);
//  - partner.example runs its own Local broker for Pat (the cross-organization case);
//  - outside.example's broker hosts Mallory (an outsider with a legitimate broker);
//  - rogue.example claims example.org addresses, and no domain document names it.
// Names and data are fictional. Domain documents exist only for federation; the Local profile never reads them.

import { Broker } from "../core/broker.ts";
import type { BrokerOptions } from "../core/broker.ts";
import { ManualClock } from "../core/clock.ts";
import { DEV_ISSUER } from "../core/identity.ts";
import type { Store } from "../core/interfaces.ts";
import { KeyRing } from "../core/keys.ts";
import { RecordingNotifier } from "../core/notify.ts";
import { ScopeRegistry } from "../core/scopes/index.ts";
import { MemorySecurityEvents } from "../core/security-events.ts";
import type { BrokerEntry, DelegateCaller, DomainDocument, HumanCaller, OrgPolicy } from "../core/types.ts";
import { InProcessFederation } from "../federation/in-process.ts";
import { StaticResolver } from "../federation/static-resolver.ts";
import { MemoryStore } from "../storage/memory.ts";

export const IDS = {
  example: "https://broker.example.org",
  partner: "https://broker.partner.example",
  outside: "https://broker.outside.example",
  rogue: "https://rogue.example",
} as const;

export const ANA = "alp:ana@example.org";
export const LEE = "alp:lee@example.org";
export const FRAN = "alp:fran@example.org";
export const PAT = "alp:pat@partner.example";
export const MALLORY = "alp:mallory@outside.example";

/** OAuth client ids (fictional). The first is on example.org's allow-list; the second is not. */
export const CLIENTS = {
  connector: "https://connector.example/client-metadata.json",
  consumer: "https://consumer-agent.example/client-metadata.json",
  unlisted: "https://unlisted-agent.example/client-metadata.json",
} as const;

export function examplePolicy(now: Date, overrides: Partial<OrgPolicy> = {}): OrgPolicy {
  return {
    alp: "0.1",
    id: "example-org",
    serial: 1,
    domains: ["example.org"],
    updated_at: now.toISOString(),
    groups: { finance: { members: [FRAN] } },
    classification: {
      rules: [
        { id: "financial-stays-in-finance", labels: ["confidential.financial"], direction: "outbound", allow: ["group:finance"], action: "reject", mode: "enforce", description: "Financial figures go only to the finance group." },
        { id: "confidential-stays-inside", labels: ["confidential.*"], direction: "both", allow: ["@org"], action: "reject", mode: "enforce", description: "Confidential fields never leave example.org." },
      ],
    },
    default_relationships: [
      {
        id: "staff",
        from: ["@org"],
        to: ["@org"],
        scopes: {
          "alp.briefing/1": {
            forward: { may: ["request", "ask_human"], fields: ["/body/topic", "/body/questions/*", "/body/depth", "/body/due_by", "/body/context"] },
            reverse: { may: ["inform", "ask_human"], fields: ["/body/points/*", "/body/as_of", "/body/confidence", "/body/follow_up"] },
          },
          "alp.availability/1": {
            forward: { may: ["request"], fields: ["/body/window", "/body/duration_minutes", "/body/timezone"] },
            reverse: { may: ["inform"], fields: ["/body/free", "/body/as_of", "/body/timezone"] },
          },
        },
      },
    ],
    clients: {
      mode: "enforce",
      allowed: [
        { client_id: CLIENTS.connector, scopes: ["alp.briefing/1", "alp.availability/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"], attestation: "vendor", class: "business", no_training: true },
        { client_id: CLIENTS.consumer, scopes: ["alp.briefing/1", "alp.availability/1"], attestation: "self", class: "consumer", no_training: false },
      ],
    },
    delivery_minimums: [{ labels: ["confidential.*"], min_class: "business" }],
    dlp: { categories: ["payment_card", "private_key", "credential", "government_id"], inbound: true },
    federation: { mode: "deny", domains: ["blocked.example"] },
    connection_requests: { inbound: "allow" },
    human_fallback: "notify_only",
    sms: false,
    ...overrides,
  };
}

export function partnerPolicy(now: Date): OrgPolicy {
  return {
    alp: "0.1",
    id: "partner",
    serial: 1,
    domains: ["partner.example"],
    updated_at: now.toISOString(),
    dlp: { categories: ["payment_card", "private_key", "credential", "government_id"], inbound: false },
  };
}

export interface Person {
  address: string;
  agent: DelegateCaller;
  /** A signed-in person with a fresh step-up at the world's current time. */
  human(): HumanCaller;
}

export interface World {
  clock: ManualClock;
  resolver: StaticResolver;
  fed: InProcessFederation;
  notifier: RecordingNotifier;
  events: MemorySecurityEvents;
  scopes: ScopeRegistry;
  example: Broker;
  partner: Broker;
  outside: Broker;
  rogue: Broker;
  ana: Person;
  lee: Person;
  fran: Person;
  pat: Person;
  mallory: Person;
  /** Publish (or republish with a higher serial) a domain's document for its broker. */
  publish(domain: string, broker: Broker, extra?: Partial<DomainDocument>): void;
}

export interface WorldOptions {
  policy?: (now: Date) => OrgPolicy;
  storeFor?: (brokerId: string) => Store;
  brokerOptions?: Partial<BrokerOptions>;
  /** Publish domain documents (federation). The Local profile works without them. Default true. */
  domainDocs?: boolean;
}

export async function buildWorld(opts: WorldOptions = {}): Promise<World> {
  const clock = new ManualClock("2026-11-09T14:00:00.000Z");
  const now = clock.now();
  const resolver = new StaticResolver();
  const fed = new InProcessFederation();
  const notifier = new RecordingNotifier();
  const events = new MemorySecurityEvents();
  const scopes = ScopeRegistry.load();
  const storeFor = opts.storeFor ?? (() => new MemoryStore());
  const serials = new Map<string, number>();

  const make = async (id: string, policies: OrgPolicy[], domains: string[]): Promise<Broker> => {
    const keys = await KeyRing.generate(now);
    await keys.prepareNext(now);
    const broker = new Broker({ id, store: storeFor(id), keys, resolver, transport: fed.transportFor(id), notifier, securityEvents: events, clock, scopes, policies, domains, ...opts.brokerOptions });
    fed.register(id, broker);
    resolver.setJwks(`${id}/.well-known/jwks.json`, () => broker.jwks());
    return broker;
  };
  const example = await make(IDS.example, [(opts.policy ?? examplePolicy)(now)], ["example.org"]);
  const partner = await make(IDS.partner, [partnerPolicy(now)], ["partner.example"]);
  const outside = await make(IDS.outside, [], ["outside.example"]);
  const rogue = await make(IDS.rogue, [], ["example.org"]);

  const entry = (b: Broker, principals: BrokerEntry["principals"] = "*"): BrokerEntry => ({
    id: b.id,
    inbox: `${b.id}/federation/inbox`,
    jwks_uri: `${b.id}/.well-known/jwks.json`,
    mcp: `${b.id}/mcp`,
    jkt: b.keys.jkts().slice(0, 4),
    principals,
  });
  const publish = (domain: string, broker: Broker, extra: Partial<DomainDocument> = {}): void => {
    const serial = (serials.get(domain) ?? 0) + 1;
    serials.set(domain, serial);
    resolver.setDomain({
      alp: "0.1",
      domain,
      serial,
      max_age: 3600,
      mode: "enforce",
      brokers: [entry(broker)],
      security_contact: [`mailto:security@${domain}`],
      ...extra,
    });
  };
  if (opts.domainDocs ?? true) {
    publish("example.org", example);
    publish("partner.example", partner);
    publish("outside.example", outside);
  }

  const person = async (broker: Broker, address: string, label: string, name: string, client: string): Promise<Person> => {
    await broker.registerPrincipal({ address, identity: { iss: DEV_ISSUER, sub: `dev-${name.toLowerCase()}` }, display_name: name, contact: { email: address.slice(address.indexOf(":") + 1) } });
    const d = await broker.registerDelegate({ principal: address, label, kind: "bridged", client_id: client });
    return {
      address,
      agent: { kind: "delegate", principal: address, delegate: d.id, client_id: client },
      human: () => ({ kind: "human", principal: address, auth: { method: "reauth-dev", at: clock.now().toISOString() } }),
    };
  };
  const ana = await person(example, ANA, "muse", "Ana", CLIENTS.connector);
  const lee = await person(example, LEE, "dot", "Lee", CLIENTS.connector);
  const fran = await person(example, FRAN, "claude", "Fran", CLIENTS.connector);
  const pat = await person(partner, PAT, "agent", "Pat", CLIENTS.connector);
  const mallory = await person(outside, MALLORY, "agent", "Mallory", CLIENTS.connector);
  // The rogue broker registers its own "ana@example.org".
  await rogue.registerPrincipal({ address: ANA, identity: { iss: "https://rogue.example", sub: "ana" }, display_name: "Ana (forged)" });
  await rogue.registerDelegate({ principal: ANA, label: "muse", client_id: CLIENTS.connector });

  return { clock, resolver, fed, notifier, events, scopes, example, partner, outside, rogue, ana, lee, fran, pat, mallory, publish };
}
