// SPDX-License-Identifier: FSL-1.1-ALv2
import type { ErrorCode, Reason } from "./types.ts";

/** An error the broker reports to its caller, with a spec error code. */
export class AlpError extends Error {
  readonly code: ErrorCode;
  /** Suggested HTTP status for bindings. */
  readonly status: number;
  readonly reasons: Reason[];

  constructor(code: ErrorCode, message: string, opts: { status?: number; reasons?: Reason[] } = {}) {
    super(message);
    this.name = "AlpError";
    this.code = code;
    this.status = opts.status ?? 400;
    this.reasons = opts.reasons ?? [{ code, detail: message }];
  }
}

export function isAlpError(err: unknown): err is AlpError {
  return err instanceof AlpError;
}

export function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
