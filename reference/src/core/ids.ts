// SPDX-License-Identifier: FSL-1.1-ALv2
import { isValid, monotonicFactory } from "ulid";
import type { Clock } from "./clock.ts";

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/** A monotonic ULID source bound to a clock (ids sort in creation order, also within one millisecond). */
export class IdSource {
  private readonly next = monotonicFactory();
  private readonly clock: Clock;
  constructor(clock: Clock) {
    this.clock = clock;
  }
  ulid(): string {
    return this.next(this.clock.now().getTime());
  }
}

export function isUlid(value: unknown): value is string {
  return typeof value === "string" && ULID_RE.test(value) && isValid(value);
}
