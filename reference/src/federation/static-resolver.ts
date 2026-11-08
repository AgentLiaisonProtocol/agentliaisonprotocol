// SPDX-License-Identifier: FSL-1.1-ALv2
// A DomainResolver backed by in-memory maps: for tests, the in-process demo, and as the contract the HTTPS
// resolver must keep. Documents are validated exactly as fetched ones would be, including
// the serial rule (a lower serial than one already served is refused).

import { checkDomainDocument } from "../core/domain.ts";
import { AlpError } from "../core/errors.ts";
import type { DomainResolver } from "../core/interfaces.ts";
import type { DomainDocument, Jwks } from "../core/types.ts";

export class StaticResolver implements DomainResolver {
  private readonly docs = new Map<string, DomainDocument>();
  private readonly serials = new Map<string, number>();
  private readonly jwksSources = new Map<string, () => Jwks>();
  /** What was looked up, in order (tests assert on it). */
  readonly lookups: string[] = [];

  setDomain(doc: DomainDocument): void {
    const checked = checkDomainDocument(structuredClone(doc), doc.domain, this.serials.get(doc.domain));
    this.docs.set(doc.domain, checked);
    this.serials.set(doc.domain, checked.serial);
  }

  removeDomain(domain: string): void {
    this.docs.delete(domain);
  }

  /** Pass a function to serve a live key ring (rotation shows up at once). */
  setJwks(uri: string, source: Jwks | (() => Jwks)): void {
    this.jwksSources.set(uri, typeof source === "function" ? source : () => structuredClone(source));
  }

  async domainDocument(domain: string): Promise<DomainDocument> {
    this.lookups.push(`domain:${domain}`);
    const doc = this.docs.get(domain);
    // A domain with no document set publishes none (the Local profile): `absent`, as the HTTPS resolver marks a 404.
    if (!doc) throw Object.assign(new AlpError("discovery_failed", "no domain document", { status: 502 }), { absent: true as const });
    return structuredClone(doc);
  }

  async jwks(uri: string): Promise<Jwks> {
    this.lookups.push(`jwks:${uri}`);
    const source = this.jwksSources.get(uri);
    if (!source) throw new AlpError("discovery_failed", "no JWKS", { status: 502 });
    return structuredClone(source());
  }
}
