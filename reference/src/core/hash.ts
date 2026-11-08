// SPDX-License-Identifier: FSL-1.1-ALv2
import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.ts";

export function base64url(data: Uint8Array | string): string {
  return Buffer.from(typeof data === "string" ? Buffer.from(data, "utf8") : data).toString("base64url");
}

/** `sha256:<base64url digest>` of raw bytes or a UTF-8 string. */
export function sha256(data: Uint8Array | string): string {
  return `sha256:${createHash("sha256").update(data).digest("base64url")}`;
}

/** `sha256:<base64url digest>` of the JCS form of a JSON value. Used for envelope, receipt and ledger hashes. */
export function hashJson(value: unknown): string {
  return sha256(canonicalize(value));
}
