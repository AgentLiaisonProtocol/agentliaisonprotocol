// SPDX-License-Identifier: FSL-1.1-ALv2
import { AlpError } from "./errors.ts";
import { PROTOCOL } from "./protocol.ts";
import type { Address, DelegateId } from "./types.ts";

// Addresses look like email addresses. The protocol form carries a `alp:` prefix; people see the bare form.
// v0.1 keeps addresses to lower-case ASCII so signatures never depend on case folding or IDNA.

const LOCAL = "[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?";
const SCHEME = PROTOCOL.addressScheme;
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DOMAIN = `(?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?`;
const DELEGATE_LABEL = "[a-z0-9](?:[a-z0-9_-]{0,30}[a-z0-9])?";

export const ADDRESS_PATTERN = `^${SCHEME}${LOCAL}@${DOMAIN}$`;
export const DELEGATE_PATTERN = `^${SCHEME}${LOCAL}@${DOMAIN}/${DELEGATE_LABEL}$`;
export const DOMAIN_PATTERN = `^${DOMAIN}$`;

const ADDRESS_RE = new RegExp(ADDRESS_PATTERN);
const DELEGATE_RE = new RegExp(DELEGATE_PATTERN);
const DOMAIN_RE = new RegExp(DOMAIN_PATTERN);
const LABEL_RE = new RegExp(`^${DELEGATE_LABEL}$`);

export function isAddress(value: unknown): value is Address {
  return typeof value === "string" && value.length <= 320 && !value.includes("..") && ADDRESS_RE.test(value);
}

export function isDelegateId(value: unknown): value is DelegateId {
  return typeof value === "string" && value.length <= 360 && !value.includes("..") && DELEGATE_RE.test(value);
}

export function isDomain(value: unknown): value is string {
  return typeof value === "string" && value.length <= 253 && !value.includes("..") && DOMAIN_RE.test(value);
}

/** Accepts `ana@example.org` or `alp:ana@example.org` in any case; returns the protocol form. */
export function parseAddress(input: string): Address {
  if (typeof input !== "string") throw new AlpError("invalid_input", "address must be a string");
  let s = input.trim().toLowerCase();
  if (!s.startsWith(SCHEME)) s = `${SCHEME}${s}`;
  if (!isAddress(s)) throw new AlpError("invalid_input", `not an ALP address: ${JSON.stringify(input)}`);
  return s;
}

/** The bare form people see: `ana@example.org`. */
export function displayAddress(address: Address): string {
  return address.startsWith(SCHEME) ? address.slice(SCHEME.length) : address;
}

export function domainOf(address: Address): string {
  const at = address.lastIndexOf("@");
  if (at < 0) throw new AlpError("invalid_input", "address has no domain");
  return address.slice(at + 1);
}

export function isDelegateLabel(label: string): boolean {
  return LABEL_RE.test(label);
}

export function delegateIdOf(address: Address, label: string): DelegateId {
  if (!isDelegateLabel(label)) throw new AlpError("invalid_input", `invalid delegate label: ${JSON.stringify(label)}`);
  return `${address}/${label}`;
}

export function parseDelegateId(id: string): { address: Address; label: string } {
  const s = id.trim().toLowerCase();
  if (!isDelegateId(s)) throw new AlpError("invalid_input", `not a delegate id: ${JSON.stringify(id)}`);
  const slash = s.lastIndexOf("/");
  return { address: s.slice(0, slash), label: s.slice(slash + 1) };
}

/** True when the delegate id belongs to the address. */
export function delegateBelongsTo(delegate: string, address: Address): boolean {
  if (!isDelegateId(delegate)) return false;
  return parseDelegateId(delegate).address === address;
}

/** Labels an agent may not take. */
export const RESERVED_DELEGATE_LABELS: readonly string[] = ["broker", "admin", "web"];
