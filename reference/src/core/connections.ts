// SPDX-License-Identifier: FSL-1.1-ALv2
// Connection requests: pending → approved | declined | expired | cancelled. Only `pending` moves.

import { AlpError } from "./errors.ts";
import type { ConnectionRequestRecord, ConnectionState } from "./types.ts";

const ALLOWED: Record<ConnectionState, readonly ConnectionState[]> = {
  pending: ["approved", "declined", "expired", "cancelled"],
  approved: [],
  declined: [],
  expired: [],
  cancelled: [],
};

export function canTransitionConnection(from: ConnectionState, to: ConnectionState): boolean {
  return ALLOWED[from].includes(to);
}

export function transitionConnection(
  rec: ConnectionRequestRecord,
  to: ConnectionState,
  now: Date,
  patch: Partial<Pick<ConnectionRequestRecord, "approved_scopes">> = {},
): ConnectionRequestRecord {
  const current = expireConnectionIfDue(rec, now);
  if (!canTransitionConnection(current.state, to)) {
    throw new AlpError("invalid_input", `connection request is ${current.state}; it cannot become ${to}`, { status: 409 });
  }
  return { ...current, ...patch, state: to, updated_at: now.toISOString() };
}

export function expireConnectionIfDue(rec: ConnectionRequestRecord, now: Date): ConnectionRequestRecord {
  if (rec.state !== "pending" || Date.parse(rec.expires_at) > now.getTime()) return rec;
  return { ...rec, state: "expired", updated_at: now.toISOString() };
}
