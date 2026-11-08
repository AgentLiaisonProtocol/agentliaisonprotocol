// SPDX-License-Identifier: FSL-1.1-ALv2
// The development broker's world (npm run dev, tests with real agents, the client-binding tests). Fictional people only.
// One Local-profile broker for example.org (spec 3.3) that also hosts an outsider at outside.example:
// - ana@example.org, the analyst, and lee@example.org, the leader: example.org's policy pre-approves alp.briefing/1,
//   alp.availability/1 and alp.status/1 between its own people, so Ana's agent can send Lee's agent those requests at
//   once. Between two staff members both directions of the default apply (spec 6.6.1), so each side may ask and answer:
//   their agents can hold a conversation in a thread, follow-up questions, clarifications and updates included;
// - mallory@outside.example, an outsider with no relationship: her agent can only ask to connect, and that request
//   reaches the person (on the web view), never Lee's agent.
// The org policy is private local configuration (spec 6.4). Its client allow-list runs in `report` mode here, so a live
// proof never fails on an unexpected client id; the known clients get the attestation and class listed below.

import { join } from "node:path";
import { displayAddress } from "./core/address.ts";
import { Broker } from "./core/broker.ts";
import type { BrokerLimits } from "./core/broker.ts";
import { DEV_ISSUER, DevIdentityVerifier } from "./core/identity.ts";
import type { DevIdentity } from "./core/identity.ts";
import type { FederationTransport, Notifier, SecurityEventSink, Store } from "./core/interfaces.ts";
import { KeyRing } from "./core/keys.ts";
import type { OrgPolicy } from "./core/types.ts";
import { StaticResolver } from "./federation/static-resolver.ts";
import { FileStore } from "./storage/file.ts";
import { MemoryStore } from "./storage/memory.ts";

export const DEV_BROKER_ID = "https://broker.example.org";
export const DEV_DOMAINS = ["example.org", "outside.example"];

export const DEV_IDENTITIES: DevIdentity[] = [
  { username: "ana", address: "alp:ana@example.org", display_name: "Ana (test analyst)" },
  { username: "lee", address: "alp:lee@example.org", display_name: "Lee (test leader)" },
  { username: "mallory", address: "alp:mallory@outside.example", display_name: "Mallory (test outsider)" },
];

/** Client ID metadata documents the hosted agent platforms publish (fetched Nov 6 and 7, 2026). */
export const KNOWN_CLIENTS = {
  claude: "https://claude.ai/oauth/mcp-oauth-client-metadata",
  /** Claude's second document, for servers that advertise private_key_jwt: it authenticates with Anthropic's key. */
  claudeConfidential: "https://claude.ai/oauth/mcp-oauth-client-metadata/confidential_client",
  claudeCode: "https://claude.ai/oauth/claude-code-client-metadata",
  chatgpt: "https://chatgpt.com/oauth/client.json",
} as const;

const CORE_SCOPES = ["alp.availability/1", "alp.briefing/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"];
const STATUS_FIELDS = ["/body/subject", "/body/ref", "/body/state", "/body/percent_complete", "/body/eta", "/body/blockers/*", "/body/updated_at"];

export function devPolicy(now: Date): OrgPolicy {
  return {
    alp: "0.1",
    id: "example-org-dev",
    serial: 1,
    domains: ["example.org"],
    updated_at: now.toISOString(),
    groups: { finance: { members: [] } },
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
            forward: { may: ["request"], fields: ["/body/window", "/body/duration_minutes", "/body/timezone", "/body/purpose"] },
            reverse: { may: ["inform"], fields: ["/body/free", "/body/as_of", "/body/timezone"] },
          },
          // Status updates in either direction, and questions about them, in one thread (spec 9).
          "alp.status/1": {
            forward: { may: ["request", "inform", "ask_human"], fields: [...STATUS_FIELDS] },
            reverse: { may: ["request", "inform", "ask_human"], fields: [...STATUS_FIELDS] },
          },
        },
      },
    ],
    clients: {
      mode: "report",
      allowed: [
        { client_id: KNOWN_CLIENTS.claude, label: "claude", scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: false },
        { client_id: KNOWN_CLIENTS.claudeConfidential, label: "claude", scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: false },
        { client_id: KNOWN_CLIENTS.claudeCode, label: "claude-code", scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: false },
        { client_id: KNOWN_CLIENTS.chatgpt, label: "chatgpt", scopes: CORE_SCOPES, attestation: "vendor", class: "business", no_training: false },
        { client_id: "pat", scopes: CORE_SCOPES, attestation: "self", class: "consumer", no_training: false },
      ],
    },
    delivery_minimums: [{ labels: ["confidential.*"], min_class: "business" }],
    dlp: { categories: ["payment_card", "private_key", "credential", "government_id"], inbound: true },
    federation: { mode: "deny", domains: ["blocked.example"] },
    connection_requests: { inbound: "allow" },
    human_fallback: "notify_only",
    sms: false,
    inbound_default: "response_only",
  };
}

/** A transport for a broker that doesn't federate: every remote delivery is unreachable. */
export const LOCAL_ONLY_TRANSPORT: FederationTransport = {
  deliver: async () => ({ kind: "unreachable", message: "this development broker doesn't federate" }),
};

export interface DevBroker {
  broker: Broker;
  store: Store;
  policies: OrgPolicy[];
  identity: DevIdentityVerifier;
}

/** Builds the example.org broker with its persisted keys and seeds the test identities (idempotent). */
export async function createDevBroker(opts: {
  dataDir?: string;
  webBaseUrl: string;
  notifier: Notifier;
  securityEvents?: SecurityEventSink;
  secret?: string;
  brokerId?: string;
  now?: Date;
  /** Message rate limits (`npm run dev` reads ALP_DEFAULT_RATE_LIMIT and ALP_OWN_AGENT_RATE_LIMIT). */
  limits?: Partial<BrokerLimits>;
}): Promise<DevBroker> {
  const now = opts.now ?? new Date();
  const store: Store = opts.dataDir ? new FileStore(join(opts.dataDir, "broker")) : new MemoryStore();
  const stored = await store.getKeyRing("federation");
  let keys: KeyRing;
  if (stored) {
    keys = KeyRing.fromJSON(stored);
  } else {
    keys = await KeyRing.generate(now);
    await keys.prepareNext(now);
    await store.putKeyRing("federation", keys.toJSON());
  }
  const policies = [devPolicy(now)];
  const broker = new Broker({
    id: opts.brokerId ?? DEV_BROKER_ID,
    store,
    keys,
    resolver: new StaticResolver(),
    transport: LOCAL_ONLY_TRANSPORT,
    notifier: opts.notifier,
    policies,
    domains: DEV_DOMAINS,
    ...(opts.securityEvents ? { securityEvents: opts.securityEvents } : {}),
    webBaseUrl: opts.webBaseUrl,
    ...(opts.limits ? { limits: opts.limits } : {}),
  });
  for (const who of DEV_IDENTITIES) {
    await broker.registerPrincipal({
      address: who.address,
      identity: { iss: DEV_ISSUER, sub: `dev-${who.username}` },
      ...(who.display_name ? { display_name: who.display_name } : {}),
      contact: { email: displayAddress(who.address) },
    });
  }
  const identity = new DevIdentityVerifier(DEV_IDENTITIES, opts.secret !== undefined ? { secret: opts.secret } : {});
  return { broker, store, policies, identity };
}
