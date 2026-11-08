// SPDX-License-Identifier: FSL-1.1-ALv2
/** All time in the broker comes from a Clock, so tests can move time. */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

/** A clock tests control. */
export class ManualClock implements Clock {
  private ms: number;
  constructor(start: Date | string | number = "2026-11-09T14:00:00.000Z") {
    this.ms = new Date(start).getTime();
  }
  now(): Date {
    return new Date(this.ms);
  }
  set(to: Date | string | number): void {
    this.ms = new Date(to).getTime();
  }
  advance(seconds: number): void {
    this.ms += seconds * 1000;
  }
}

export function iso(d: Date): string {
  return d.toISOString();
}

export function addSeconds(d: Date, seconds: number): Date {
  return new Date(d.getTime() + seconds * 1000);
}
