// SPDX-License-Identifier: FSL-1.1-ALv2
// Personal access tokens (spec 5.7): for clients that can only send a fixed header (Claude's
// "request headers", an agent that writes its own API connector, scripts). Minted only on the web view after a fresh
// sign-in; bound to one principal and one delegate label (client_id `pat`, attestation `self`); scopes `read` and/or
// `send`; opaque with 256 bits of entropy, shown once and stored as a hash; at most 30 days for organization
// principals and 90 days for others; revocable at any time.

import { randomBytes } from "node:crypto";
import { ulid } from "ulid";
import type { Broker } from "../core/broker.ts";
import type { PrincipalRecord } from "../core/types.ts";
import { PAT_CLIENT_ID } from "../core/types.ts";
import { sha256b64u } from "./state.ts";
import type { BindingStore, PatRecord } from "./state.ts";

export { PAT_CLIENT_ID };
export const PAT_PREFIX = "alpat_";

export function looksLikePat(token: string): boolean {
  return token.startsWith(PAT_PREFIX) && token.length === PAT_PREFIX.length + 43;
}

export async function mintPat(args: {
  broker: Broker;
  state: BindingStore;
  principal: PrincipalRecord;
  label: string;
  scopes: ("read" | "send")[];
  days: number;
  maxDays: number;
  now: Date;
}): Promise<{ token: string; record: PatRecord }> {
  const { broker, state, principal, now } = args;
  const scopes = [...new Set(args.scopes)].filter((s) => s === "read" || s === "send");
  if (scopes.length === 0) throw new Error("choose at least one scope");
  const days = Math.max(1, Math.min(Math.floor(args.days), args.maxDays));
  const d = await broker.registerDelegate({ principal: principal.address, label: args.label, kind: "bridged", client_id: PAT_CLIENT_ID, attestation: "self", class: "consumer" });
  const token = `${PAT_PREFIX}${randomBytes(32).toString("base64url")}`;
  const record: PatRecord = {
    id: ulid(now.getTime()),
    hash: sha256b64u(token),
    principal_id: principal.principal_id,
    delegate: d.id,
    binding: d.created_at,
    label: d.label,
    scopes,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + days * 86400_000).toISOString(),
  };
  await state.putPat(record);
  return { token, record };
}

/** The token's record, looked up by the token's SHA-256 (the token itself is never stored). */
export async function findPat(state: BindingStore, token: string): Promise<PatRecord | undefined> {
  return (await state.findPatByHash(sha256b64u(token))) ?? undefined;
}

export async function patsOf(state: BindingStore, principalId: string): Promise<PatRecord[]> {
  return state.listPats(principalId);
}

/** Revoke one of the person's tokens. Only `revoked_at` is written, so a request that read the token before can't put it back. */
export async function revokePat(state: BindingStore, principalId: string, id: string, now: Date): Promise<PatRecord | undefined> {
  const r = await state.getPat(id);
  if (!r || r.principal_id !== principalId) return undefined;
  return (await state.revokePat(id, now.toISOString())) ?? undefined;
}

/** Revoke every token a delegate holds (when the person revokes the delegate). */
export async function revokePatsOfDelegate(state: BindingStore, delegate: string, now: Date): Promise<number> {
  let n = 0;
  for (const r of await state.listPatsOfDelegate(delegate)) {
    if (!r.revoked_at) {
      await state.revokePat(r.id, now.toISOString());
      n++;
    }
  }
  return n;
}

