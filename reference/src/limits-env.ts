// SPDX-License-Identifier: FSL-1.1-ALv2
// The message rate limits an operator can set in the environment (`npm start`, `npm run dev`; SELF-HOST.md, "Rate
// limits"):
//   ALP_DEFAULT_RATE_LIMIT     between two people, when their terms set none (default 120/3600): one bucket per sending
//                              person and counterparty at the sender's broker, and per receiving person and sender at
//                              the recipient's
//   ALP_OWN_AGENT_RATE_LIMIT   between one person's own agents (default 600/3600): one bucket per sending agent and
//                              receiving agent, apart from the person's limits with other people
// Each is `count/seconds`: at most `count` messages in any `seconds`, with `count` at most 100,000 (the memory and file
// stores keep every hit in a window) and `seconds` at most 30 days.

import type { BrokerLimits } from "./core/broker.ts";
import type { RateLimit } from "./core/types.ts";

/** The largest `count` a limit from the environment may have: the memory and file stores keep every hit in a window. */
export const RATE_LIMIT_COUNT_MAX = 100_000;

/** A `count/seconds` limit from the environment, or undefined when the variable is unset or empty. */
export function rateLimitEnv(name: string, env: NodeJS.ProcessEnv = process.env): RateLimit | undefined {
  const v = env[name];
  if (v === undefined || v.trim() === "") return undefined;
  const m = /^\s*([0-9]+)\s*\/\s*([0-9]+)\s*$/.exec(v);
  const count = Number(m?.[1]);
  const perSeconds = Number(m?.[2]);
  if (!m || !Number.isSafeInteger(count) || !Number.isSafeInteger(perSeconds) || count < 1 || count > RATE_LIMIT_COUNT_MAX || perSeconds < 1 || perSeconds > 30 * 86400) {
    throw new Error(`${name} must be count/seconds, for example 600/3600 (each at least 1; count at most 100000, seconds at most 30 days)`);
  }
  return { count, per_seconds: perSeconds };
}

/** ALP_DEFAULT_RATE_LIMIT and ALP_OWN_AGENT_RATE_LIMIT as the Broker's `limits` option (only those that are set). */
export function rateLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): Partial<BrokerLimits> {
  const between = rateLimitEnv("ALP_DEFAULT_RATE_LIMIT", env);
  const own = rateLimitEnv("ALP_OWN_AGENT_RATE_LIMIT", env);
  return { ...(between ? { defaultRateLimit: between } : {}), ...(own ? { ownAgentRateLimit: own } : {}) };
}
