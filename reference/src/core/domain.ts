// SPDX-License-Identifier: FSL-1.1-ALv2
// Domain documents (public): https://<domain>/.well-known/alp.json or
// https://alp.<domain>/.well-known/alp.json (the MTA-STS pattern, spec 4.3).
// One home broker per address: the broker whose explicit list holds it, else the single "*" broker, else none.

import { calculateJwkThumbprint } from "jose";
import { domainOf } from "./address.ts";
import { AlpError } from "./errors.ts";
import { PROTOCOL } from "./protocol.ts";
import { assertValid } from "./spec-schemas.ts";
import type { Address, BrokerEntry, DomainDocument, Jwk, Jwks } from "./types.ts";

/** Recommended max_age; the schema caps it at 24 hours. */
export const RECOMMENDED_MAX_AGE_SECONDS = 3600;
export const MAX_AGE_LIMIT_SECONDS = 86400;
/** Deny entries (de-listed brokers, revoked keys) keep applying this long after a failed refresh. */
export const RESTRICTION_PERSIST_SECONDS = 7 * 24 * 3600;
/** Fetch caps for documents and JWKS (the fetcher enforces them). */
export const FETCH_LIMITS = { maxBytes: 64 * 1024, timeoutMs: 5000, envelopeMaxBytes: 1024 * 1024 } as const;

export function wellKnownUrls(domain: string): string[] {
  const path = `/.well-known/${PROTOCOL.wellKnownFile}`;
  return [`https://${domain}${path}`, `https://${PROTOCOL.hostLabel}.${domain}${path}`];
}

export function txtRecordName(domain: string): string {
  return `${PROTOCOL.txtLabel}.${domain}`;
}

/**
 * `v=ALP1; id=<id>` (spec 4.7): the id is 1 to 32 letters and digits and SHOULD equal the document's serial. The record
 * never points anywhere; a record with any other member is ignored (null). `serial` is set when the id is a number.
 */
export function parseTxtRecord(value: string): { id: string; serial?: number } | null {
  const m = new RegExp(`^v=${PROTOCOL.txtVersion};[ ]?id=([A-Za-z0-9]{1,32})$`).exec(value);
  if (!m?.[1]) return null;
  return /^[0-9]{1,15}$/.test(m[1]) ? { id: m[1], serial: Number(m[1]) } : { id: m[1] };
}

/**
 * Validate a fetched domain document. `lastSerial` is the highest serial already accepted for the domain;
 * a lower one is refused (rollback). Throws `discovery_failed`.
 */
export function checkDomainDocument(value: unknown, expectedDomain: string, lastSerial?: number): DomainDocument {
  const doc = assertValid<DomainDocument>("domainDocument", value, "discovery_failed");
  if (doc.domain !== expectedDomain) throw new AlpError("discovery_failed", `document names ${doc.domain}, expected ${expectedDomain}`, { status: 502 });
  if (lastSerial !== undefined && doc.serial < lastSerial) throw new AlpError("discovery_failed", "document serial went backwards", { status: 502 });
  const ids = new Set<string>();
  const listed = new Set<string>();
  let stars = 0;
  for (const b of doc.brokers) {
    if (ids.has(b.id)) throw new AlpError("discovery_failed", `broker ${b.id} is listed twice`, { status: 502 });
    ids.add(b.id);
    if (b.principals === "*") {
      stars++;
      continue;
    }
    for (const p of b.principals) {
      if (domainOf(p) !== doc.domain) throw new AlpError("discovery_failed", "a domain can only list its own addresses", { status: 502 });
      if (listed.has(p)) throw new AlpError("discovery_failed", "overlapping authorizations are invalid", { status: 502 });
      listed.add(p);
    }
  }
  if (stars > 1) throw new AlpError("discovery_failed", "at most one broker may take every address", { status: 502 });
  // Every endpoint of an entry sits on the entry's own origin (spec 4.2.1).
  for (const b of doc.brokers) {
    for (const [name, url] of [["inbox", b.inbox], ["jwks_uri", b.jwks_uri], ["mcp", b.mcp], ["rest", b.rest], ["operator_statement", b.operator_statement]] as const) {
      if (url === undefined) continue;
      let origin: string;
      try {
        origin = new URL(url).origin;
      } catch {
        throw new AlpError("discovery_failed", `${name} of ${b.id} is not a URL`, { status: 502 });
      }
      if (origin !== b.id) throw new AlpError("discovery_failed", `${name} of ${b.id} is not on the broker's own origin`, { status: 502 });
    }
  }
  return doc;
}

export function homeBroker(doc: DomainDocument, address: Address): BrokerEntry | undefined {
  if (domainOf(address) !== doc.domain) return undefined;
  return doc.brokers.find((b) => b.principals !== "*" && b.principals.includes(address)) ?? doc.brokers.find((b) => b.principals === "*");
}

/** RFC 7638 thumbprint of a public JWK (OKP or EC). */
export async function jwkThumbprint(k: Jwk): Promise<string> {
  return calculateJwkThumbprint(k.kty === "OKP" ? { kty: "OKP", crv: String(k.crv), x: String(k.x) } : { kty: "EC", crv: String(k.crv), x: String(k.x), y: String(k.y) }, "sha256");
}

/**
 * The keys a broker may sign federation objects with (spec 4.8 rule 1): the `alp_use: federation` keys of its JWKS
 * whose RFC 7638 thumbprint the domain document pins in the broker's entry and that aren't revoked. Every other key
 * is ignored, even one present in the JWKS (a signature by it fails as `bad_signature`). A key whose `kid` isn't its
 * thumbprint is ignored too, so a kid can never name a key other than the pinned one.
 */
export async function pinnedFederationKeys(jwks: unknown, entry: BrokerEntry, revoked: readonly string[] = []): Promise<Jwks> {
  const set = assertValid<Jwks>("jwks", jwks, "discovery_failed");
  const keys: Jwk[] = [];
  for (const k of set.keys) {
    if (k.d !== undefined || k.alp_use !== "federation") continue;
    const jkt = await jwkThumbprint(k);
    if (!entry.jkt.includes(jkt) || revoked.includes(jkt) || k.kid !== jkt) continue;
    keys.push(k);
  }
  return { keys };
}

/** Thumbprints the document reports compromised (spec 4.8 rule 5). */
export function revokedKeys(doc: DomainDocument | null): string[] {
  return doc?.revoked_jkt?.map((r) => r.jkt) ?? [];
}

export function keyCompromisedSince(doc: DomainDocument, jkt: string): string | undefined {
  return doc.revoked_jkt?.find((r) => r.jkt === jkt)?.compromised_since;
}
