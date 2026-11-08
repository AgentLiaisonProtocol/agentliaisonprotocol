// SPDX-License-Identifier: FSL-1.1-ALv2
// Connection requests an agent files (spec 6.2.1): the broker holds them as `pending_principal` and notifies the
// person; nothing is sent until the person approves on the web view with a fresh sign-in, choosing their own terms.
// Approval then goes through the core's human path (Broker.requestConnection with a HumanCaller), so the requester's
// terms are sealed by the person and become active when the other side accepts.

import { ulid } from "ulid";
import type { BindingStore, PendingConnection } from "../oauth/state.ts";

export const PENDING_TTL_DAYS = 14;
export const PENDING_PER_DAY = 5;

export async function pendingFor(state: BindingStore, principalId: string, now: Date): Promise<PendingConnection[]> {
  const out: PendingConnection[] = [];
  for (const p of await state.listPending(principalId)) {
    if (p.state === "pending_principal" && Date.parse(p.expires_at) <= now.getTime()) {
      p.state = "expired";
      p.updated_at = now.toISOString();
      await state.putPending(p);
    }
    out.push(p);
  }
  return out.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

/** `retryAfter`: whole seconds until the oldest of today's requests is a day old. */
export type FileResult = { kind: "filed" | "existing"; request: PendingConnection } | { kind: "rate_limited"; retryAfter: number };

export async function filePending(state: BindingStore, input: Omit<PendingConnection, "id" | "state" | "created_at" | "updated_at" | "expires_at">, now: Date): Promise<FileResult> {
  const mine = await pendingFor(state, input.principal_id, now);
  const open = mine.find((p) => p.state === "pending_principal" && p.to === input.to);
  if (open) return { kind: "existing", request: open };
  const today = mine.filter((p) => now.getTime() - Date.parse(p.created_at) < 86400_000);
  if (today.length >= PENDING_PER_DAY) {
    const oldest = Math.min(...today.map((p) => Date.parse(p.created_at)));
    return { kind: "rate_limited", retryAfter: Math.max(1, Math.ceil((oldest + 86400_000 - now.getTime()) / 1000)) };
  }
  const at = now.toISOString();
  const request: PendingConnection = {
    ...input,
    id: ulid(now.getTime()),
    state: "pending_principal",
    created_at: at,
    updated_at: at,
    expires_at: new Date(now.getTime() + PENDING_TTL_DAYS * 86400_000).toISOString(),
  };
  await state.putPending(request);
  return { kind: "filed", request };
}

export async function getPending(state: BindingStore, principalId: string, id: string): Promise<PendingConnection | undefined> {
  const p = await state.getPending(id);
  return p && p.principal_id === principalId ? p : undefined;
}

export async function settlePending(state: BindingStore, id: string, next: PendingConnection["state"], result: PendingConnection["result"] | undefined, now: Date): Promise<void> {
  const p = await state.getPending(id);
  if (!p) return;
  p.state = next;
  if (result) p.result = result;
  p.updated_at = now.toISOString();
  await state.putPending(p);
}
