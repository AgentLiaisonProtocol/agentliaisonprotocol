// SPDX-License-Identifier: FSL-1.1-ALv2
// The HTTPS DomainResolver (spec 4.3 to 4.8). Every fetch goes through the hardened fetcher.
//  - Location 1, https://<domain>/.well-known/alp.json; location 2 (https://alp.<domain>/...) only
//    after a 404, 410 or a name with no address records. Any other failure is temporary: no fallback.
//  - Grants expire: a document (and the brokers, keys and endpoints in it) is never used past max_age (at most
//    24 hours) from when it was fetched, even when the refresh fails. Then the domain is unavailable (discovery_failed).
//  - Restrictions persist: every revoked_jkt entry seen is applied for 7 days after it was last seen, even when a
//    newer document drops it or refreshes fail.
//  - Rollback: the highest serial accepted per domain is remembered; a lower one, or the same one with different
//    content, is refused.
//  - Failures are cached for 60 seconds (configurable, 60 to 300); discovery of domains never seen before is rate-limited.
//  - The TXT record `_alp.<domain>` is only a hint: a higher id than the cached serial triggers a refresh.
//    It never points anywhere.
//  - Forced refreshes (the core asks after an unknown kid) happen at most once a minute per document or JWKS.
// Errors thrown are AlpError("discovery_failed") with a generic message: fetch details never reach a remote party.
// Internal detail goes to `diagnostics` (local only).

import { resolveTxt } from "node:dns/promises";
import { isDomain } from "../core/address.ts";
import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import { MAX_AGE_LIMIT_SECONDS, RESTRICTION_PERSIST_SECONDS, checkDomainDocument, parseTxtRecord, txtRecordName, wellKnownUrls } from "../core/domain.ts";
import { AlpError, errMessage } from "../core/errors.ts";
import { hashJson } from "../core/hash.ts";
import type { DomainResolver } from "../core/interfaces.ts";
import { PROTOCOL } from "../core/protocol.ts";
import type { DomainDocument, Jwks } from "../core/types.ts";
import { checkEndpointOrigins } from "./domain-authority.ts";
import { FetchFailure } from "./fetcher.ts";
import type { HardenedFetcher } from "./fetcher.ts";

/** DNS TXT lookups for the `_alp.<domain>` hint. */
export interface TxtLookup {
  resolveTxt(name: string): Promise<string[][]>;
}

export const systemTxtLookup: TxtLookup = { resolveTxt: (name) => resolveTxt(name) };

/** A TXT lookup backed by a map (development and tests). */
export class StaticTxtLookup implements TxtLookup {
  private readonly records = new Map<string, string[]>();
  set(name: string, values: string[]): void {
    this.records.set(name, [...values]);
  }
  delete(name: string): void {
    this.records.delete(name);
  }
  async resolveTxt(name: string): Promise<string[][]> {
    const v = this.records.get(name);
    if (!v) throw Object.assign(new Error("no TXT record"), { code: "ENOTFOUND" });
    return v.map((s) => [s]);
  }
}

/** discovery_failed, plus whether the domain definitely publishes no document (404/410 or no address at both locations). */
export class DiscoveryError extends AlpError {
  readonly absent: boolean;
  constructor(absent: boolean) {
    super("discovery_failed", absent ? "the domain publishes no document" : "discovery failed", { status: 503 });
    this.name = "DiscoveryError";
    this.absent = absent;
  }
}

export interface ResolverDiagnostic {
  at: string;
  domain?: string;
  uri?: string;
  event:
    | "fetched"
    | "fallback_location"
    | "failed"
    | "invalid"
    | "expired"
    | "failure_cached"
    | "new_domain_rate_limited"
    | "refresh_rate_limited"
    | "kept_cached"
    | "txt_hint"
    | "jwks_fetched"
    | "jwks_failed";
  detail?: string;
}

export interface ResolverOptions {
  fetcher: HardenedFetcher;
  clock?: Clock;
  /** The TXT hint. Default: none (no DNS TXT lookups). Use systemTxtLookup in production if wanted. */
  txt?: TxtLookup;
  /** Seconds a failure is cached (60 to 300). Default 60. */
  failureCacheSeconds?: number;
  /**
   * Discovery fetches for never-seen domains per minute, for each requester (the `budget` key a caller passes, such as
   * the remote address of an inbound request). Default 30. Unkeyed lookups (this broker's own sends) share one budget.
   */
  newDomainsPerMinute?: number;
  /** All discovery fetches for never-seen domains per minute, whoever asked: a backstop. Default ten times the above. */
  newDomainsPerMinuteTotal?: number;
  /** Minimum seconds between forced refreshes of one document or JWKS. Default 60. */
  forcedRefreshSeconds?: number;
  /** Minimum seconds between TXT checks per domain. Default 300. */
  txtCheckSeconds?: number;
  /** Upper bound for caching a JWKS; also bounded by the max_age of the documents that list it. Default 3600. */
  jwksMaxAgeSeconds?: number;
  onDiagnostic?: (d: ResolverDiagnostic) => void;
}

interface CachedDoc {
  doc: DomainDocument;
  hash: string;
  fetchedAt: number;
  expiresAt: number;
  txtCheckedAt: number;
  lastForced: number;
}

interface CachedJwks {
  jwks: Jwks;
  expiresAt: number;
  lastForced: number;
}

type FetchOutcome = { ok: true; rec: CachedDoc } | { ok: false; absent: boolean };

const MAX_REVOKED = 64;

export class HttpsDomainResolver implements DomainResolver {
  private readonly fetcher: HardenedFetcher;
  private readonly clock: Clock;
  private readonly txt: TxtLookup | undefined;
  private readonly failureMs: number;
  private readonly newPerMinute: number;
  private readonly forcedMs: number;
  private readonly txtMs: number;
  private readonly jwksMaxAgeMs: number;
  private readonly onDiagnostic: ((d: ResolverDiagnostic) => void) | undefined;

  private readonly docs = new Map<string, CachedDoc>();
  /** Highest serial accepted per domain, and that document's hash (rollback protection). */
  private readonly accepted = new Map<string, { serial: number; hash: string }>();
  private readonly failures = new Map<string, { until: number; absent: boolean }>();
  private readonly revoked = new Map<string, Map<string, { compromised_since: string; lastSeen: number }>>();
  private readonly jwksCache = new Map<string, CachedJwks>();
  /** Per jwks_uri: the smallest max_age (ms) of the documents that list it. */
  private readonly jwksBound = new Map<string, number>();
  private readonly discoveryTimes = new Map<string, number[]>();
  private discoveryTotal: number[] = [];
  private readonly newPerMinuteTotal: number;
  /** Local diagnostics, newest last (never sent to a remote party). */
  readonly diagnostics: ResolverDiagnostic[] = [];

  constructor(opts: ResolverOptions) {
    this.fetcher = opts.fetcher;
    this.clock = opts.clock ?? systemClock;
    this.txt = opts.txt;
    this.failureMs = Math.min(300, Math.max(60, opts.failureCacheSeconds ?? 60)) * 1000;
    this.newPerMinute = opts.newDomainsPerMinute ?? 30;
    this.newPerMinuteTotal = opts.newDomainsPerMinuteTotal ?? this.newPerMinute * 10;
    this.forcedMs = (opts.forcedRefreshSeconds ?? 60) * 1000;
    this.txtMs = (opts.txtCheckSeconds ?? 300) * 1000;
    this.jwksMaxAgeMs = Math.min(opts.jwksMaxAgeSeconds ?? 3600, MAX_AGE_LIMIT_SECONDS) * 1000;
    this.onDiagnostic = opts.onDiagnostic;
  }

  async domainDocument(domain: string, opts: { refresh?: boolean; budget?: string } = {}): Promise<DomainDocument> {
    if (!isDomain(domain)) throw new DiscoveryError(false);
    const now = this.clock.now().getTime();
    const cached = this.docs.get(domain);
    const valid = cached && now < cached.expiresAt ? cached : undefined;
    if (valid) {
      let refresh = opts.refresh === true;
      if (refresh && now - valid.lastForced < this.forcedMs) {
        this.diag({ domain, event: "refresh_rate_limited" });
        refresh = false;
      }
      if (!refresh && (await this.txtSaysNewer(domain, valid, now))) refresh = true;
      if (!refresh) return this.view(domain, valid.doc, now);
      valid.lastForced = now;
      const fresh = await this.fetchAndCheck(domain, now, opts.budget);
      if (fresh.ok) return this.view(domain, fresh.rec.doc, now);
      // The cached document is still within max_age, so it stays usable.
      this.diag({ domain, event: "kept_cached" });
      return this.view(domain, valid.doc, now);
    }
    if (cached) {
      // Past max_age: never used again, whatever happens to the refresh.
      this.docs.delete(domain);
      this.diag({ domain, event: "expired", detail: `serial ${cached.doc.serial}` });
    }
    const fresh = await this.fetchAndCheck(domain, now, opts.budget);
    if (!fresh.ok) throw new DiscoveryError(fresh.absent);
    return this.view(domain, fresh.rec.doc, now);
  }

  async jwks(uri: string, opts: { refresh?: boolean } = {}): Promise<Jwks> {
    const now = this.clock.now().getTime();
    const cached = this.jwksCache.get(uri);
    const valid = cached && now < cached.expiresAt ? cached : undefined;
    if (valid && !opts.refresh) return structuredClone(valid.jwks);
    if (valid && opts.refresh && now - valid.lastForced < this.forcedMs) {
      this.diag({ uri, event: "refresh_rate_limited" });
      return structuredClone(valid.jwks);
    }
    let value: unknown;
    try {
      value = await this.fetcher.getJson(uri);
      if (!value || typeof value !== "object" || !Array.isArray((value as { keys?: unknown }).keys)) throw new Error("not a JWK Set");
    } catch (err) {
      this.diag({ uri, event: "jwks_failed", detail: errMessage(err) });
      if (valid) return structuredClone(valid.jwks);
      throw new DiscoveryError(false);
    }
    const ttl = Math.min(this.jwksMaxAgeMs, this.jwksBound.get(uri) ?? this.jwksMaxAgeMs);
    const jwks = value as Jwks;
    this.jwksCache.set(uri, { jwks, expiresAt: now + ttl, lastForced: opts.refresh ? now : (cached?.lastForced ?? 0) });
    this.diag({ uri, event: "jwks_fetched", detail: `${jwks.keys.length} keys` });
    return structuredClone(jwks);
  }

  /** The cached document's serial, if any (diagnostics and tests). */
  cachedSerial(domain: string): number | undefined {
    return this.docs.get(domain)?.doc.serial;
  }

  // -------------------------------------------------------------------------------------------

  private async fetchAndCheck(domain: string, now: number, budget?: string): Promise<FetchOutcome> {
    const failed = this.failures.get(domain);
    if (failed && now < failed.until) {
      this.diag({ domain, event: "failure_cached" });
      return { ok: false, absent: failed.absent };
    }
    if (!this.accepted.has(domain) && !this.allowNewDomain(now, budget ?? "")) {
      this.diag({ domain, event: "new_domain_rate_limited" });
      return { ok: false, absent: false };
    }
    const [first, second] = wellKnownUrls(domain) as [string, string];
    let value: unknown;
    try {
      try {
        value = await this.fetcher.getJson(first);
      } catch (err) {
        if (!(err instanceof FetchFailure) || (err.kind !== "not_found" && err.kind !== "no_address")) throw err;
        this.diag({ domain, event: "fallback_location", detail: err.message });
        value = await this.fetcher.getJson(second);
      }
    } catch (err) {
      const absent = err instanceof FetchFailure && (err.kind === "not_found" || err.kind === "no_address");
      this.failures.set(domain, { until: now + this.failureMs, absent });
      this.diag({ domain, event: "failed", detail: errMessage(err) });
      return { ok: false, absent };
    }
    let doc: DomainDocument;
    let hash: string;
    try {
      const prev = this.accepted.get(domain);
      doc = checkDomainDocument(value, domain, prev?.serial);
      checkEndpointOrigins(doc);
      hash = hashJson(doc);
      if (prev && prev.serial === doc.serial && prev.hash !== hash) throw new Error("same serial with different content");
    } catch (err) {
      this.failures.set(domain, { until: now + this.failureMs, absent: false });
      this.diag({ domain, event: "invalid", detail: errMessage(err) });
      return { ok: false, absent: false };
    }
    const maxAgeMs = Math.min(doc.max_age, MAX_AGE_LIMIT_SECONDS) * 1000;
    const rec: CachedDoc = { doc, hash, fetchedAt: now, expiresAt: now + maxAgeMs, txtCheckedAt: now, lastForced: this.docs.get(domain)?.lastForced ?? 0 };
    this.docs.set(domain, rec);
    this.accepted.set(domain, { serial: doc.serial, hash });
    this.failures.delete(domain);
    this.rememberRevocations(domain, doc, now);
    for (const b of doc.brokers) this.jwksBound.set(b.jwks_uri, Math.min(this.jwksBound.get(b.jwks_uri) ?? Infinity, maxAgeMs));
    this.diag({ domain, event: "fetched", detail: `serial ${doc.serial}` });
    return { ok: true, rec };
  }

  /** Per requester, so junk sender domains from one source can't use up first contact for everyone else (spec 4.3). */
  private allowNewDomain(now: number, key: string): boolean {
    this.discoveryTotal = this.discoveryTotal.filter((t) => now - t < 60_000);
    const mine = (this.discoveryTimes.get(key) ?? []).filter((t) => now - t < 60_000);
    if (mine.length >= this.newPerMinute || this.discoveryTotal.length >= this.newPerMinuteTotal) {
      this.discoveryTimes.set(key, mine);
      return false;
    }
    this.discoveryTimes.set(key, [...mine, now]);
    this.discoveryTotal.push(now);
    if (this.discoveryTimes.size > 10_000) for (const [k, v] of this.discoveryTimes) if (!v.some((t) => now - t < 60_000)) this.discoveryTimes.delete(k);
    return true;
  }

  private rememberRevocations(domain: string, doc: DomainDocument, now: number): void {
    if (!doc.revoked_jkt?.length) return;
    const m = this.revoked.get(domain) ?? new Map<string, { compromised_since: string; lastSeen: number }>();
    for (const r of doc.revoked_jkt) m.set(r.jkt, { compromised_since: r.compromised_since, lastSeen: now });
    this.revoked.set(domain, m);
  }

  /** A copy of the document with every remembered revocation still in force added back. */
  private view(domain: string, doc: DomainDocument, now: number): DomainDocument {
    const out = structuredClone(doc);
    const remembered = this.revoked.get(domain);
    if (!remembered) return out;
    const listed = new Set((out.revoked_jkt ?? []).map((r) => r.jkt));
    const extra: { jkt: string; compromised_since: string }[] = [];
    for (const [jkt, r] of remembered) {
      if (now - r.lastSeen > RESTRICTION_PERSIST_SECONDS * 1000) {
        remembered.delete(jkt);
        continue;
      }
      if (!listed.has(jkt)) extra.push({ jkt, compromised_since: r.compromised_since });
    }
    if (extra.length) out.revoked_jkt = [...(out.revoked_jkt ?? []), ...extra].slice(0, MAX_REVOKED);
    return out;
  }

  /** True when the TXT hint shows a serial above the cached one (checked at most every txtCheckSeconds). */
  private async txtSaysNewer(domain: string, cached: CachedDoc, now: number): Promise<boolean> {
    if (!this.txt || now - cached.txtCheckedAt < this.txtMs) return false;
    cached.txtCheckedAt = now;
    let records: string[][];
    try {
      records = await Promise.race([
        this.txt.resolveTxt(txtRecordName(domain)),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("TXT lookup timed out")), 2000).unref()),
      ]);
    } catch {
      return false;
    }
    // Only a single record of ours counts; one with any other member, or more than one, is ignored.
    const ours = records.map((chunks) => chunks.join("")).filter((v) => v.trim().startsWith(`v=${PROTOCOL.txtVersion}`));
    if (ours.length !== 1) return false;
    const hint = parseTxtRecord((ours[0] as string).trim());
    // The id SHOULD equal the serial (spec 4.7). A numeric id above the cached serial is a refresh hint; a
    // non-numeric id that differs from the cached serial is one too.
    if (!hint || (hint.serial !== undefined ? hint.serial <= cached.doc.serial : hint.id === String(cached.doc.serial))) return false;
    this.diag({ domain, event: "txt_hint", detail: `TXT id ${hint.id} > cached serial ${cached.doc.serial}` });
    return true;
  }

  private diag(d: Omit<ResolverDiagnostic, "at">): void {
    const entry: ResolverDiagnostic = { at: this.clock.now().toISOString(), ...d };
    this.diagnostics.push(entry);
    if (this.diagnostics.length > 1000) this.diagnostics.splice(0, this.diagnostics.length - 1000);
    this.onDiagnostic?.(entry);
  }
}
