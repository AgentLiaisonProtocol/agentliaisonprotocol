// SPDX-License-Identifier: FSL-1.1-ALv2
// Rate and replay windows outside the core's own checks: failed sign-ins, OIDC sign-ins started, dynamic
// registrations, client metadata fetches, and the request limits of the connector sign-in page and the web view.
// They use the Store's two window methods (recordOnce and hitRateLimit), so a hosted broker passes its Postgres store
// and every instance shares them; a local broker keeps them in memory, as it always has (MemoryWindows). Not here: the
// federation inbox's per-address limit and request-signature nonces, which each instance keeps for itself
// (src/federation/inbox.ts); envelope replay is checked in the Store.

import { secondsUntilOldestLeaves } from "./interfaces.ts";
import type { RateLimitHit, Store } from "./interfaces.ts";

export type Windows = Pick<Store, "recordOnce" | "hitRateLimit">;

/** Hits on `key` within the last `windowSeconds`, without adding one (a limit of 0 only counts). */
export async function windowCount(w: Windows, key: string, now: Date, windowSeconds: number): Promise<number> {
  return (await w.hitRateLimit(key, now, windowSeconds, 0)).count;
}

/** Add a hit on `key` whatever the count; returns the count including it. */
export async function windowHit(w: Windows, key: string, now: Date, windowSeconds: number): Promise<number> {
  return (await w.hitRateLimit(key, now, windowSeconds, Number.MAX_SAFE_INTEGER)).count;
}

/** One process's windows, with the Store's semantics, bounded in size. */
export class MemoryWindows implements Windows {
  private readonly hits = new Map<string, number[]>();
  private readonly seen = new Map<string, number>();
  private readonly maxKeys: number;

  constructor(maxKeys = 20_000) {
    this.maxKeys = maxKeys;
  }

  async recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean> {
    const t = now.getTime();
    const until = this.seen.get(key);
    if (until !== undefined && until > t) return false;
    if (this.seen.size >= this.maxKeys) for (const [k, u] of this.seen) if (u <= t) this.seen.delete(k);
    this.seen.set(key, Date.parse(expiresAt));
    return true;
  }

  async hitRateLimit(key: string, now: Date, windowSeconds: number, limit: number): Promise<RateLimitHit> {
    const t = now.getTime();
    const recent = (this.hits.get(key) ?? []).filter((x) => x > t - windowSeconds * 1000);
    if (recent.length >= limit) {
      if (recent.length) this.hits.set(key, recent);
      else this.hits.delete(key);
      return { allowed: false, count: recent.length, retryAfter: secondsUntilOldestLeaves(recent, t, windowSeconds) };
    }
    if (this.hits.size >= this.maxKeys) {
      // Nothing here uses a window longer than a day.
      for (const [k, times] of this.hits) if (!times.some((x) => x > t - 86400_000)) this.hits.delete(k);
    }
    recent.push(t);
    this.hits.set(key, recent);
    return { allowed: true, count: recent.length, retryAfter: secondsUntilOldestLeaves(recent, t, windowSeconds) };
  }
}
