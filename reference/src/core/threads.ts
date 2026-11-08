// SPDX-License-Identifier: FSL-1.1-ALv2
// The thread state machine (spec 9.2, 9.3): open → negotiating → agreed (needs ratification) → committed → done |
// expired | cancelled. A thread is a conversation: after the first message (a type in the scope's `starts`), either
// side keeps sending messages in it until it ends. Each later message is a reply (it names an earlier message of the
// thread, and the scope's `replies` map must let its type answer that one's; an accept or a counter answers the other
// party's latest proposal) or a follow-up (it names none: a request, an inform, an ask_human or an error, or a type in
// `starts`), and the thread's state must accept its type: requests and informs in `open` (in a scope that negotiates,
// informs only after the commit), the negotiation types in `negotiating` and `agreed`, informs in `committed`. A commit
// is single-use and must carry the agreed terms_hash and both principals' unexpired ratification hashes. A thread ends
// with an `ack` `completed`, a `decline` of its first message, of a proposal or of agreed terms, or expiry: once its
// latest message has expired (while terms are on the table or agreed, its latest proposal or accept). It holds at most
// MAX_THREAD_MESSAGES messages besides one that ends it. Each broker keeps its own principal's copy of the thread.

import type { CompiledScope } from "./scopes/index.ts";
import type { Address, MessageType, ScopeId, Sha256, ThreadRecord, ThreadState, ThreadTransition } from "./types.ts";

export const TERMINAL_STATES: readonly ThreadState[] = ["done", "expired", "cancelled"];

/** A thread takes at most this many messages, besides one that ends it (spec 9.2); then a new thread continues. */
export const MAX_THREAD_MESSAGES = 200;

/** While terms are on the table or agreed, only these prolong the thread (spec 9.2). */
const PROLONG_NEGOTIATION: readonly MessageType[] = ["propose", "counter", "accept"];

/** How many messages a thread holds. One person's own agents' copy applies each message twice (as received, then sent). */
export function messageCount(thread: ThreadRecord): number {
  return new Set(thread.history.map((h) => h.envelope_id)).size;
}

/** The latest proposal of the thread (its latest `propose` or `counter`), which an accept or a counter answers. */
export function latestProposal(thread: ThreadRecord | null): ThreadTransition | undefined {
  if (!thread) return undefined;
  for (let i = thread.history.length - 1; i >= 0; i--) {
    const h = thread.history[i];
    if (h && (h.type === "propose" || h.type === "counter")) return h;
  }
  return undefined;
}

/**
 * Whether `type` may follow up in an existing thread without naming a message (spec 9.3): a request, an inform, an
 * ask_human or an error, or a type the scope lets start a thread (so propose in alp.meeting/1).
 */
export function mayFollowUp(scope: CompiledScope, type: MessageType): boolean {
  return ["request", "inform", "ask_human", "error"].includes(type) || (scope.def.starts as MessageType[]).includes(type);
}

/**
 * The types a thread in `state` accepts in this scope (spec 9.2). The conversation runs in `open` (and, after a
 * commit, in `committed`); the negotiation states take only their own types, so nothing said around a negotiation can
 * change agreed terms or stand in for an accept or a commit. In a scope that negotiates, `inform` reports what happened
 * after the commit, so it is accepted only in `committed`.
 */
export function acceptedTypes(scope: CompiledScope, state: ThreadState): MessageType[] {
  const negotiable = scope.def.negotiable;
  let types: MessageType[];
  switch (state) {
    case "open":
      types = negotiable ? ["request", "propose", "decline", "ack", "ask_human", "error"] : ["request", "inform", "decline", "ack", "ask_human", "error"];
      break;
    case "negotiating":
      types = ["counter", "accept", "decline", "ack", "ask_human", "error"];
      break;
    case "agreed":
      types = ["commit", "decline", "ack", "ask_human", "error"];
      break;
    case "committed":
      types = ["inform", "ack", "ask_human", "error"];
      break;
    default:
      types = [];
  }
  return types.filter((t) => scope.types.has(t));
}

export interface ThreadMessage {
  thread: string;
  principal: Address;
  /** Stamped on a thread it starts: the thread belongs to this principal, not to the address (spec 5.2). */
  principal_id?: string;
  counterparty: Address;
  scope: ScopeId;
  envelope_id: string;
  type: MessageType;
  direction: "in" | "out";
  at: string;
  expires_at: string;
  in_reply_to?: string;
  /** Type and direction of the message replied to (looked up by the caller in this thread). */
  reply_to?: { type: MessageType; direction: "in" | "out" };
  terms_hash?: Sha256;
  ratifications?: [Sha256, Sha256];
  ack_status?: "received" | "completed" | "ratified";
}

export type ThreadResult =
  | { ok: true; thread: ThreadRecord }
  | { ok: false; code: "thread_state" | "needs_ratification"; detail: string };

const fail = (detail: string, code: "thread_state" | "needs_ratification" = "thread_state"): ThreadResult => ({ ok: false, code, detail });

/** Lazily expire a thread whose life (spec 9.2) ran out before it was committed or closed. */
export function expireIfDue(thread: ThreadRecord, now: Date): ThreadRecord {
  if (TERMINAL_STATES.includes(thread.state) || thread.state === "committed") return thread;
  if (Date.parse(thread.expires_at) > now.getTime()) return thread;
  return { ...thread, state: "expired", updated_at: now.toISOString() };
}

/** Why a thread in `state` doesn't take `type`, for the sender's own agent (spec 6.8: the sender's side only). */
function notAccepted(scope: CompiledScope, state: ThreadState, type: MessageType): string {
  const takes = acceptedTypes(scope, state).join(", ");
  const a = state === "open" || state === "agreed" ? "an" : "a";
  if (type === "inform" && scope.def.negotiable && state !== "committed") {
    return `in ${scope.id}, inform reports what happened after the commit, so ${a} ${state} thread doesn't take it (it takes ${takes})`;
  }
  if (state === "agreed") return `agreed terms take only ${takes}; new terms need a new thread`;
  return `${a} ${state} ${scope.id} thread doesn't take ${type} (it takes ${takes})`;
}

export function applyToThread(scope: CompiledScope, thread: ThreadRecord | null, msg: ThreadMessage, now: Date): ThreadResult {
  const def = scope.def;
  const current = thread ? expireIfDue(thread, now) : null;
  if (current) {
    if (current.counterparty !== msg.counterparty || current.scope !== msg.scope || current.principal !== msg.principal || (current.principal_id !== undefined && msg.principal_id !== undefined && current.principal_id !== msg.principal_id)) {
      return fail("the thread belongs to another relationship or scope");
    }
    if (TERMINAL_STATES.includes(current.state)) return fail(`the thread is ${current.state}; anything more needs a new thread`);
    if (!acceptedTypes(scope, current.state).includes(msg.type)) return fail(notAccepted(scope, current.state, msg.type));
  } else {
    if (!(def.starts as string[]).includes(msg.type)) return fail(`${msg.type} cannot start a ${scope.id} thread`);
    if (msg.in_reply_to) return fail("a new thread cannot reply to anything");
  }
  if (msg.in_reply_to) {
    // A reply: it names an earlier message of the thread, from either side, whose type the scope lets it answer.
    if (!msg.reply_to) return fail("in_reply_to names no message in this thread");
    if (!(def.replies[msg.reply_to.type] ?? []).includes(msg.type)) return fail(`${msg.type} cannot reply to ${msg.reply_to.type} in ${scope.id}`);
    if (msg.type === "accept" || msg.type === "counter") {
      // An accept or a counter answers the other party's latest proposal: never the sender's own, nor one replaced since.
      if (msg.reply_to.direction === msg.direction) return fail(`${msg.type} answers the other party's proposal, never your own`);
      if (latestProposal(current)?.envelope_id !== msg.in_reply_to) return fail(`${msg.type} answers the latest proposal in the thread; a later one replaced this one`);
    }
  } else if (current && !mayFollowUp(scope, msg.type)) {
    // A follow-up names no message: a request, an inform, an ask_human or an error, or a type that may start a thread.
    return fail(`${msg.type} must reply to a message`);
  }

  const from = current?.state ?? null;
  let to: ThreadState = current?.state ?? "open";
  const next: ThreadRecord = current
    ? structuredClone(current)
    : { id: msg.thread, principal: msg.principal, ...(msg.principal_id !== undefined ? { principal_id: msg.principal_id } : {}), counterparty: msg.counterparty, scope: msg.scope, state: "open", created_at: msg.at, updated_at: msg.at, expires_at: msg.expires_at, history: [] };

  switch (msg.type) {
    case "request":
    case "inform":
    case "ask_human":
    case "error":
      if (!current) to = "open";
      break;
    case "propose":
    case "counter":
      if (!def.negotiable) return fail(`${scope.id} does not negotiate`);
      to = "negotiating";
      delete next.terms_hash;
      delete next.ratifications;
      delete next.proposer;
      break;
    case "accept":
      if (!def.negotiable) return fail(`${scope.id} does not negotiate`);
      if (!msg.terms_hash) return fail("accept must carry terms_hash");
      to = "agreed";
      next.terms_hash = msg.terms_hash;
      delete next.ratifications;
      // The accepted proposal's author: a reply to our own proposal means we proposed.
      next.proposer = msg.reply_to?.direction === "out" ? "me" : "counterparty";
      break;
    case "commit": {
      if (current?.commit) return fail("this thread already has a commit");
      if (!msg.terms_hash || msg.terms_hash !== current?.terms_hash) return fail("commit terms differ from the agreed terms");
      const mine = current.ratifications?.mine?.hash;
      const theirs = current.ratifications?.theirs?.hash;
      if (!mine || !theirs) return fail("both people must ratify the agreed terms first", "needs_ratification");
      const given = new Set(msg.ratifications ?? []);
      if (given.size !== 2 || !given.has(mine) || !given.has(theirs)) return fail("the commit does not reference both ratifications", "needs_ratification");
      // Both records must still be valid when the commit is sent and when it is received (spec 9.4).
      const live = (r: { expires_at?: string } | undefined): boolean => Date.parse(r?.expires_at ?? "") > now.getTime();
      if (!live(current.ratifications?.mine?.record) || !live(current.ratifications?.theirs?.record)) return fail("a ratification of the agreed terms has expired; new terms need a new thread");
      const committerIsProposer = (msg.direction === "out") === (current.proposer === "me");
      if (def.committer === "proposer" && !committerIsProposer) return fail("only the proposer may commit in this scope");
      to = "committed";
      next.commit = { envelope_id: msg.envelope_id, direction: msg.direction, at: msg.at };
      break;
    }
    case "decline": {
      // A decline of the thread's first message, of a proposal or of the agreed terms closes the thread: done before
      // agreement, cancelled in agreed. A decline of a later request turns down that request only (spec 9.2).
      const closes = msg.in_reply_to === current?.history[0]?.envelope_id || ["propose", "counter", "accept"].includes(msg.reply_to?.type ?? "");
      if (closes) to = current?.state === "agreed" ? "cancelled" : "done";
      break;
    }
    case "ack":
      // Either side closes the thread with an ack whose status is completed (spec 9.2), except agreed terms: they end
      // with a commit, a decline (which cancels them) or expiry.
      if (msg.ack_status === "completed") {
        if (current?.state === "agreed") return fail("agreed terms end with a commit, or with a decline that cancels them; an ack can't close them");
        to = "done";
      }
      break;
  }
  if (current && !TERMINAL_STATES.includes(to) && messageCount(current) >= MAX_THREAD_MESSAGES && !current.history.some((h) => h.envelope_id === msg.envelope_id)) {
    return fail(`the thread holds ${MAX_THREAD_MESSAGES} messages, the most one thread takes, so it takes only a message that ends it; continue in a new thread`);
  }
  next.state = to;
  next.updated_at = msg.at;
  // Each message keeps the thread open at least as long as it lives itself; while terms are on the table or agreed,
  // only a proposal or an accept does, so acknowledgements and questions can't keep terms waiting (spec 9.2).
  const prolongs = (from !== "negotiating" && from !== "agreed") || PROLONG_NEGOTIATION.includes(msg.type);
  if (prolongs && Date.parse(msg.expires_at) > Date.parse(next.expires_at)) next.expires_at = msg.expires_at;
  next.history = [...next.history, { envelope_id: msg.envelope_id, type: msg.type, direction: msg.direction, from, to, at: msg.at }];
  return { ok: true, thread: next };
}
