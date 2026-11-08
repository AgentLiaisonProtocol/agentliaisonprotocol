// SPDX-License-Identifier: FSL-1.1-ALv2
// The DLP hook contract (spec 6.9). Inputs: principal_id, counterparty, direction, scope, labels,
// pointer, text. Verdicts: allow | block | redact spans | require justification | notify. It has a timeout and
// fails closed by default. Verdict ids go in decision.policy_ids.
// Adapters to an organization's DLP service (Microsoft Purview processContent, Google Sensitive Data Protection, ICAP)
// are deployment choices outside the spec; `npm start` connects none.

import type { Address, DlpCategory, OrgPolicy, PrincipalId, ScopeId } from "../types.ts";

export interface DlpInput {
  principal_id: PrincipalId;
  principal: Address;
  counterparty: Address;
  direction: "outbound" | "inbound";
  scope: ScopeId;
  labels: string[];
  /** Envelope-relative pointer: `/note` or a free-text field. */
  pointer: string;
  text: string;
}

export type DlpVerdict =
  | { verdict: "allow"; id?: string }
  | { verdict: "notify"; id: string }
  | { verdict: "block"; id: string; categories?: DlpCategory[] }
  | { verdict: "redact"; id: string; spans: [number, number][] }
  | { verdict: "require_justification"; id: string };

export interface DlpHook {
  readonly id: string;
  check(input: DlpInput): Promise<DlpVerdict>;
}

/**
 * `npm start` gives the Broker no DLP hook, so the sample check below runs. A policy whose `dlp.hook` names an outside
 * DLP service would get the sample check in its place without a word, so a broker started that way refuses it.
 */
export function refuseUnconnectedDlpHook(policy: OrgPolicy, source: string): OrgPolicy {
  if (policy.dlp?.hook !== undefined) {
    throw new Error(`${source}: dlp.hook names an outside DLP service, and this broker connects none (only the sample check would run). Remove dlp.hook, or implement DlpHook (src/core/policy/dlp.ts) and pass it to the Broker in src/main.ts`);
  }
  return policy;
}

/** Run a hook with a timeout. Errors and timeouts block unless the org set on_error: allow. */
export async function runDlp(hook: DlpHook, input: DlpInput, opts: { timeoutMs?: number; onError?: "block" | "allow" } = {}): Promise<DlpVerdict> {
  const timeoutMs = opts.timeoutMs ?? 2000;
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      hook.check(input),
      new Promise<DlpVerdict>((_, reject) => {
        timer = setTimeout(() => reject(new Error("dlp timeout")), timeoutMs);
      }),
    ]);
  } catch {
    return opts.onError === "allow" ? { verdict: "allow", id: `${hook.id}:error-allowed` } : { verdict: "block", id: `${hook.id}:error` };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const PATTERNS: [DlpCategory, RegExp][] = [
  ["private_key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["credential", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["credential", /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b/],
  ["credential", /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ["credential", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/],
  ["government_id", /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/],
];

/** The sample regex DLP the reference ships: payment cards (Luhn), private keys, credentials, US SSNs. */
export class SampleDlp implements DlpHook {
  readonly id = "sample-dlp";
  private readonly categories: Set<DlpCategory>;

  constructor(categories: DlpCategory[] = ["payment_card", "private_key", "credential", "government_id"]) {
    this.categories = new Set(categories);
  }

  async check(input: DlpInput): Promise<DlpVerdict> {
    const found = new Set<DlpCategory>();
    for (const [cat, re] of PATTERNS) if (this.categories.has(cat) && re.test(input.text)) found.add(cat);
    if (this.categories.has("payment_card")) {
      for (const m of input.text.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) {
        const digits = m[0].replace(/[ -]/g, "");
        if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
          found.add("payment_card");
          break;
        }
      }
    }
    if (found.size === 0) return { verdict: "allow" };
    const categories = [...found].sort();
    return { verdict: "block", id: `${this.id}:${categories.join("+")}`, categories };
  }
}
