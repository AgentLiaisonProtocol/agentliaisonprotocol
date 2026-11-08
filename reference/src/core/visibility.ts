// SPDX-License-Identifier: FSL-1.1-ALv2
// What one agent may read (spec 5.4, 6.11, 12.1.4): one rule for the inbox, the thread view and acknowledgements,
// whatever the binding. vectors/delivery/visibility.json holds the cases.

import { meetsConstraints } from "./policy/org-policy.ts";
import type { Attestation, Constraints, DelegateClass, DelegateId, MessageStatus } from "./types.ts";

export interface ReadableMessage {
  direction: "in" | "out";
  status: MessageStatus;
  held_until?: string;
  /** When this broker stored it: for a received message, when it received it. */
  stored_at?: string;
  /** `created_at`: for a sent message, when this broker signed it. */
  envelope: { from: { delegate?: DelegateId }; to: { delegate?: DelegateId }; constraints?: Constraints; created_at?: string };
}

export interface Reader {
  id: DelegateId;
  attestation: Attestation;
  class: DelegateClass;
  /** When this binding started (spec 5.4): an earlier binding with the same delegate id is another agent. */
  since?: string;
}

/**
 * A received message is visible to an agent if it is addressed to the person or to this agent, isn't held (or its
 * hold has ended), and the agent meets its delivery constraints with the terms recorded for its client. A sent message
 * is visible only to the agent that sent it, or to all of the person's agents when the broker sent it for the person.
 * "This agent" is this binding: a received message addressed to the same delegate id that its broker received before
 * the binding started, or a sent message its broker signed for that delegate id before then, belongs to an earlier
 * agent with that label and stays hidden. A sent message is judged by when it was signed, not stored: its record is
 * stored only once the recipient's receipt is back, which may be after a new binding started.
 */
export function agentMayRead(m: ReadableMessage, reader: Reader, client: { no_training?: boolean; retention_days?: number } | undefined, now: Date): boolean {
  const e = m.envelope;
  const before = (at: string | undefined): boolean => reader.since !== undefined && at !== undefined && Date.parse(at) < Date.parse(reader.since);
  if (m.direction === "out") return e.from.delegate === undefined || (e.from.delegate === reader.id && !before(e.created_at));
  if (e.to.delegate !== undefined && (e.to.delegate !== reader.id || before(m.stored_at))) return false;
  if (m.status === "held" && (m.held_until === undefined || Date.parse(m.held_until) > now.getTime())) return false;
  return meetsConstraints(e.constraints, reader, client);
}

/**
 * Whether this binding acknowledged a received message (spec 5.4): an acknowledgement that an earlier binding with the
 * same label made doesn't count for this one.
 */
export function ackedBy(m: { acked_by: Readonly<Record<string, string>> }, id: DelegateId, since: string | undefined): boolean {
  const at = m.acked_by[id];
  return at !== undefined && (since === undefined || Date.parse(at) >= Date.parse(since));
}
