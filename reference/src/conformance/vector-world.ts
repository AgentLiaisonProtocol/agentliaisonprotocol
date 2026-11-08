// SPDX-License-Identifier: FSL-1.1-ALv2
// The conformance vectors' shared fixture (vectors/world.json) turned into reference brokers, so every vector runs
// through the reference's own code paths: its parser, canonicalizer, verifier, resolver checks, evaluator and stores.
// TEST-ONLY keys from vectors/keys/TEST-ONLY-private-keys.json; never use them outside tests.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Broker, receiptKey, replayKey } from "../core/broker.ts";
import type { BrokerOptions } from "../core/broker.ts";
import { ManualClock, addSeconds, iso } from "../core/clock.ts";
import { checkDomainDocument } from "../core/domain.ts";
import { signReceipt } from "../core/envelope.ts";
import { AlpError } from "../core/errors.ts";
import type { DomainResolver } from "../core/interfaces.ts";
import { KeyRing } from "../core/keys.ts";
import { RecordingNotifier } from "../core/notify.ts";
import { ScopeRegistry } from "../core/scopes/index.ts";
import { MemorySecurityEvents } from "../core/security-events.ts";
import type { DelegateRecord, DomainDocument, Jwk, Jwks, OrgPolicy, PrincipalRecord, RelationshipGrant } from "../core/types.ts";
import { MemoryStore } from "../storage/memory.ts";

export const VECTOR_DIR = process.env["ALP_VECTOR_DIR"] ?? fileURLToPath(new URL("../../../vectors/", import.meta.url));

export function readVector<T = unknown>(path: string): T {
  return JSON.parse(readFileSync(join(VECTOR_DIR, path), "utf8")) as T;
}

export interface VectorPrincipal {
  address: string;
  principal_id: string;
  delegate?: string;
  attestation?: DelegateRecord["attestation"];
  class?: DelegateRecord["class"];
  client_id?: string;
}

export interface VectorWorld {
  now: string;
  clock_skew_seconds: number;
  brokers: Record<string, string>;
  principals: Record<string, VectorPrincipal>;
  domain_documents: Record<string, DomainDocument>;
  jwks: Record<string, Jwks>;
  org_policies: Record<string, OrgPolicy>;
  delegates: Record<string, { principal: string; client_id: string; attestation: DelegateRecord["attestation"]; class: DelegateRecord["class"]; no_training?: boolean; retention_days?: number }>;
}

export const world = readVector<VectorWorld>("world.json");
const testKeys = readVector<{ keys: Record<string, Jwk> }>("keys/TEST-ONLY-private-keys.json").keys;

/** A key ring holding one TEST-ONLY Ed25519 key from the vectors. */
export function testKeyRing(name: string): KeyRing {
  const k = testKeys[name];
  if (!k || k.kty !== "OKP" || typeof k.d !== "string" || typeof k.kid !== "string") throw new Error(`no TEST-ONLY Ed25519 key ${name}`);
  return KeyRing.fromJSON({
    version: 1,
    keys: [
      {
        kid: k.kid,
        public_jwk: { kty: "OKP", crv: "Ed25519", x: String(k.x), kid: k.kid, alg: "Ed25519", use: "sig", alp_use: "federation" },
        private_jwk: { kty: "OKP", crv: "Ed25519", x: String(k.x), d: k.d, kid: k.kid },
        created_at: "2026-11-01T00:00:00.000Z",
        status: "active",
      },
    ],
  });
}

/**
 * A DomainResolver over the vectors' documents: `docs` maps a domain to a key of world.domain_documents (a domain
 * left out publishes no document), `lastSeen` is the highest serial already accepted per domain. Documents go
 * through the reference's own checkDomainDocument, which refuses a rollback.
 */
export class VectorResolver implements DomainResolver {
  private readonly docs: Record<string, string>;
  private readonly lastSeen: Record<string, number>;

  constructor(docs: Record<string, string>, lastSeen: Record<string, number> = {}) {
    this.docs = docs;
    this.lastSeen = lastSeen;
  }

  async domainDocument(domain: string): Promise<DomainDocument> {
    const key = this.docs[domain];
    const doc = key ? world.domain_documents[key] : undefined;
    if (!doc) throw Object.assign(new AlpError("discovery_failed", `${domain} publishes no document`), { absent: true });
    return checkDomainDocument(structuredClone(doc), domain, this.lastSeen[domain]);
  }

  async jwks(uri: string): Promise<Jwks> {
    const set = world.jwks[uri];
    if (!set) throw new AlpError("discovery_failed", "no such JWKS");
    return structuredClone(set);
  }
}

/** The broker's TEST-ONLY key, by its id. */
const KEY_FOR: Record<string, string> = {
  "https://broker.example.org": "broker.example.org/federation-1",
  "https://broker.partner.example": "broker.partner.example/federation-1",
};

export interface VectorBrokerOptions {
  id: string;
  /** Domains this broker serves. */
  domains: string[];
  now: string;
  /** Domain → key of world.domain_documents. Default: every current document. */
  docs?: Record<string, string>;
  lastSeen?: Record<string, number>;
  grants?: RelationshipGrant[];
  extra?: Partial<BrokerOptions>;
}

export interface VectorBroker {
  broker: Broker;
  store: MemoryStore;
  clock: ManualClock;
}

export const CURRENT_DOCS: Record<string, string> = { "example.org": "example.org@42", "partner.example": "partner.example@7", "outside.example": "outside.example@3" };

/** A reference broker for one vector case: the world's principals, delegates and policies for its domains. */
export async function vectorBroker(o: VectorBrokerOptions): Promise<VectorBroker> {
  const clock = new ManualClock(o.now);
  const store = new MemoryStore();
  const keyName = KEY_FOR[o.id];
  const keys = keyName ? testKeyRing(keyName) : await KeyRing.generate(clock.now());
  const policies = o.domains.flatMap((d) => (world.org_policies[d] ? [world.org_policies[d] as OrgPolicy] : []));
  const broker = new Broker({
    id: o.id,
    store,
    keys,
    resolver: new VectorResolver(o.docs ?? CURRENT_DOCS, o.lastSeen ?? {}),
    transport: { deliver: async () => ({ kind: "unreachable", message: "the vectors never deliver" }) },
    notifier: new RecordingNotifier(),
    securityEvents: new MemorySecurityEvents(),
    clock,
    scopes: ScopeRegistry.load(),
    policies,
    domains: o.domains,
    ...o.extra,
  });
  const at = iso(clock.now());
  for (const p of Object.values(world.principals)) {
    if (!o.domains.includes(p.address.slice(p.address.lastIndexOf("@") + 1))) continue;
    const rec: PrincipalRecord = { principal_id: p.principal_id, address: p.address, identity: { iss: "https://idp.vectors.invalid", sub: p.principal_id }, status: "active", created_at: at };
    await store.putPrincipal(rec);
  }
  for (const [id, d] of Object.entries(world.delegates)) {
    const owner = await store.getPrincipal(d.principal);
    if (!owner) continue;
    await store.putDelegate({ id, principal: d.principal, principal_id: owner.principal_id, label: id.slice(id.lastIndexOf("/") + 1), kind: "bridged", client_id: d.client_id, attestation: d.attestation, class: d.class, status: "active", created_at: at });
  }
  for (const g of o.grants ?? []) await store.putGrant(structuredClone(g));
  return { broker, store, clock };
}

/** Seed the replay window with an envelope this broker already answered (the original receipt is stored too). */
export async function seedSeen(v: VectorBroker, seen: { origin_broker: string; id: string; envelope_hash: string; expires_at: string }): Promise<void> {
  const now = v.clock.now();
  await v.store.recordOnce(replayKey(seen.origin_broker, seen.id), iso(addSeconds(new Date(seen.expires_at), 600)), now);
  const receipt = await signReceipt(
    { alp: "0.1", id: "01M7090000SEEDRECE1PT00000", envelope_id: seen.id, envelope_hash: seen.envelope_hash, status: "accepted", created_at: iso(now), expires_at: iso(addSeconds(now, 3600)), origin_broker: v.broker.id, aud: seen.origin_broker },
    v.broker.keys,
  );
  await v.store.putReceipt(receiptKey(seen.origin_broker, seen.id), receipt);
}
