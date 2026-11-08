// SPDX-License-Identifier: FSL-1.1-ALv2
// The domain authority's side: build a domain document that names each broker and pins its keys, and check the
// rules core/domain.ts checkDomainDocument leaves out (spec 4.2.1: every endpoint on the broker's own origin).
//
// The document is public and authenticated by TLS for the domain (spec 4.2); v0.1 has no signature inside it
// (a signed JWKS, `alp-jwks+jws`, is future work). Org policy is never published (spec 6.4): it stays in
// the broker's private configuration, so there is nothing here to sign or serve for it.

import { RECOMMENDED_MAX_AGE_SECONDS, checkDomainDocument } from "../core/domain.ts";
import { AlpError } from "../core/errors.ts";
import type { KeyRing } from "../core/keys.ts";
import { ALP_VERSION } from "../core/types.ts";
import type { Address, BrokerEntry, BrokerId, DomainDocument } from "../core/types.ts";

/** The paths the reference serves on a broker's origin. */
export const FEDERATION_PATHS = {
  inbox: "/federation/inbox",
  jwks: "/.well-known/jwks.json",
} as const;

/** The most thumbprints one broker entry may pin (schema). */
export const MAX_PINS = 4;

export interface BrokerListing {
  id: BrokerId;
  /**
   * Every key ring whose public keys the broker publishes at its jwks_uri: the federation ring, and the `http` ring
   * when it signs requests. All are pinned, because a JWKS holding an unpinned key is refused outright.
   */
  keys: KeyRing[];
  principals: "*" | Address[];
  inbox?: string;
  jwks_uri?: string;
  mcp?: string;
  rest?: string;
  operator_statement?: string;
}

export function brokerEntry(l: BrokerListing): BrokerEntry {
  const jkt = [...new Set(l.keys.flatMap((k) => k.jkts()))];
  if (jkt.length === 0) throw new AlpError("invalid_input", "a broker entry pins at least one key");
  if (jkt.length > MAX_PINS) throw new AlpError("invalid_input", `a broker entry pins at most ${MAX_PINS} keys; prune retired keys first`);
  return {
    id: l.id,
    inbox: l.inbox ?? `${l.id}${FEDERATION_PATHS.inbox}`,
    jwks_uri: l.jwks_uri ?? `${l.id}${FEDERATION_PATHS.jwks}`,
    ...(l.mcp !== undefined ? { mcp: l.mcp } : {}),
    ...(l.rest !== undefined ? { rest: l.rest } : {}),
    jkt,
    principals: l.principals,
    ...(l.operator_statement !== undefined ? { operator_statement: l.operator_statement } : {}),
  };
}

export interface DomainDocumentInput {
  domain: string;
  serial: number;
  brokers: BrokerEntry[];
  maxAge?: number;
  mode?: DomainDocument["mode"];
  securityContact?: string[];
  revoked?: { jkt: string; compromised_since: string }[];
  updatedAt?: Date;
}

/** Build and check a domain document. `lastSerial` is the serial already published; the new one must be higher. */
export function buildDomainDocument(input: DomainDocumentInput, lastSerial?: number): DomainDocument {
  if (lastSerial !== undefined && input.serial <= lastSerial) throw new AlpError("invalid_input", "a new document needs a higher serial");
  const doc: DomainDocument = {
    alp: ALP_VERSION,
    domain: input.domain,
    serial: input.serial,
    max_age: input.maxAge ?? RECOMMENDED_MAX_AGE_SECONDS,
    mode: input.mode ?? "enforce",
    brokers: input.brokers,
    ...(input.revoked?.length ? { revoked_jkt: input.revoked } : {}),
    security_contact: input.securityContact ?? [`mailto:security@${input.domain}`],
    ...(input.updatedAt ? { updated_at: input.updatedAt.toISOString() } : {}),
  };
  const checked = checkDomainDocument(structuredClone(doc), input.domain);
  checkEndpointOrigins(checked);
  return checked;
}

/** Spec 4.2.1: inbox, jwks_uri, mcp, rest and operator_statement must be on the entry's own origin. Throws `discovery_failed`. */
export function checkEndpointOrigins(doc: DomainDocument): void {
  for (const b of doc.brokers) {
    const urls: [string, string | undefined][] = [
      ["inbox", b.inbox],
      ["jwks_uri", b.jwks_uri],
      ["mcp", b.mcp],
      ["rest", b.rest],
      ["operator_statement", b.operator_statement],
    ];
    for (const [name, url] of urls) {
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
}
