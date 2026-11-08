// SPDX-License-Identifier: FSL-1.1-ALv2
// oidc-provider storage adapter over a BindingStore (memory, file or Postgres). One instance per model (Grant,
// Session, AccessToken, AuthorizationCode, RefreshToken, Interaction, Client, ReplayDetection...). Keys are SHA-256
// hashes of the ids. oidc-provider also copies each artifact's id into its payload (`jti`), and an opaque token's id is
// the token itself, so for the models whose id is a credential (ID_IS_SECRET in state.ts) the payload is stored without
// it and the id is put back on lookup: the store never holds a usable refresh token, authorization code or session
// cookie. Every method is one store call (atomic on its own), so any instance of a hosted broker can answer any step
// of a flow.

import type { Adapter, AdapterPayload } from "oidc-provider";
import { ID_IS_SECRET, REUSED_FIELD, sha256b64u, withoutRawIds } from "./state.ts";
import type { BindingStore, JsonRecord } from "./state.ts";

function toJson(payload: AdapterPayload): JsonRecord {
  return JSON.parse(JSON.stringify(payload)) as JsonRecord;
}

function fromJson(payload: JsonRecord): AdapterPayload {
  return structuredClone(payload) as AdapterPayload;
}

/** Seconds a just-rotated refresh token may be presented once more (an overlapping refresh), before reuse revokes the grant. */
export const REUSE_INTERVAL_SECONDS = 30;

/**
 * Dynamically registered clients that go unused expire (spec 5.6.4; SELF-HOST "before the URL is shared"): a
 * registration lives this many days, and each use moves its expiry forward again.
 */
export const REGISTRATION_IDLE_DAYS = 30;

export class StateAdapter implements Adapter {
  private readonly store: BindingStore;
  private readonly name: string;

  constructor(store: BindingStore, name: string) {
    this.store = store;
    this.name = name;
  }

  /** The payload as found by its id: the id put back as `jti` where it was left out (ID_IS_SECRET). */
  private withId(id: string, p: JsonRecord): AdapterPayload {
    const out = fromJson(p) as AdapterPayload & { [REUSED_FIELD]?: unknown };
    delete out[REUSED_FIELD];
    if (ID_IS_SECRET.has(this.name) && out.jti === undefined) out.jti = id;
    return out;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    const now = Date.now();
    let expiresAt = expiresIn ? now + expiresIn * 1000 : undefined;
    // oidc-provider stores dynamic registrations with no expiry; an unused one would count against the registration
    // total forever.
    if (this.name === "Client" && expiresAt === undefined) expiresAt = now + REGISTRATION_IDLE_DAYS * 86400_000;
    await this.store.oidcPut(this.name, sha256b64u(id), withoutRawIds(this.name, toJson(payload), (jti) => jti === id), expiresAt);
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const key = sha256b64u(id);
    const now = Date.now();
    const p = await this.store.oidcGet(this.name, key, now);
    if (!p) return undefined;
    if (this.name === "Client") {
      // In use: keep the registration another REGISTRATION_IDLE_DAYS (written at most once a day).
      const until = now + REGISTRATION_IDLE_DAYS * 86400_000;
      if (typeof p["alp_touched"] !== "number" || now - p["alp_touched"] > 86400_000) {
        await this.store.oidcPut(this.name, key, { ...p, alp_touched: now }, until);
      }
      delete p["alp_touched"];
    }
    // A refresh token rotated less than REUSE_INTERVAL_SECONDS ago works exactly once more, so two overlapping
    // refreshes from one client (parallel tool calls when the access token expires) don't end the connection. A third
    // use, or any reuse after the interval, still revokes the whole grant (spec 5.6.7).
    const consumed = p["consumed"];
    if (this.name === "RefreshToken" && typeof consumed === "number" && p[REUSED_FIELD] === undefined) {
      const nowSec = Math.floor(now / 1000);
      if (nowSec - consumed <= REUSE_INTERVAL_SECONDS && (await this.store.oidcTakeReuse(this.name, key, nowSec, REUSE_INTERVAL_SECONDS))) {
        const copy = this.withId(id, p) as AdapterPayload & { consumed?: unknown };
        delete copy.consumed;
        return copy;
      }
    }
    return this.withId(id, p);
  }

  /** Single use (the broker's own records: OIDC login transactions and hand-offs): the payload, deleted as it is read. */
  async take(id: string): Promise<AdapterPayload | undefined> {
    const p = await this.store.oidcTake(this.name, sha256b64u(id), Date.now());
    return p ? this.withId(id, p) : undefined;
  }

  // Looked up by uid or user code, the id isn't known, so a payload of ID_IS_SECRET comes back without `jti`.
  // oidc-provider reads sessions found by uid only to check them (the interaction's account, a token's session
  // binding) and never saves them, so a session found this way doesn't need its id.
  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const p = await this.store.oidcFindBy(this.name, "userCode", userCode, Date.now());
    return p ? fromJson(p) : undefined;
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const p = await this.store.oidcFindBy(this.name, "uid", uid, Date.now());
    return p ? fromJson(p) : undefined;
  }

  async consume(id: string): Promise<void> {
    // The first consumption time is kept, so the reuse interval can't be stretched by refreshing again inside it.
    await this.store.oidcConsume(this.name, sha256b64u(id), Math.floor(Date.now() / 1000));
  }

  async destroy(id: string): Promise<void> {
    await this.store.oidcDelete(this.name, sha256b64u(id));
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.store.oidcDeleteByGrant(this.name, grantId);
  }
}

/** Every grant the authorization server holds for one account and client (to revoke them with a delegate). */
export async function grantIdsFor(store: BindingStore, accountId: string, clientId: string): Promise<string[]> {
  return store.oidcGrantIds(accountId, clientId, Date.now());
}

/** Revoke every OAuth grant (and its codes and tokens) one account holds for one client; returns the grant ids. */
export async function revokeClientGrants(store: BindingStore, accountId: string, clientId: string): Promise<string[]> {
  const grantIds = await grantIdsFor(store, accountId, clientId);
  for (const grantId of grantIds) {
    for (const model of ["AccessToken", "RefreshToken", "AuthorizationCode"]) await new StateAdapter(store, model).revokeByGrantId(grantId);
    await new StateAdapter(store, "Grant").destroy(grantId);
  }
  return grantIds;
}
