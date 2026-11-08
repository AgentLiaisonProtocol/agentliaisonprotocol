// SPDX-License-Identifier: FSL-1.1-ALv2
// Which OAuth clients may finish a sign-in at this broker, and how a client becomes a delegate (spec 5.4, 5.6).
//
// - Redirect URIs: exact match against what the client registered (or its client ID metadata document lists), and the
//   host must be one the operator allows: by default the documented callback hosts of the hosted agent platforms
//   (claude.ai, chatgpt.com) plus loopback, which RFC 8252 lets native clients use on any port.
// - The delegate label never comes from tool arguments. It is derived from the verified client: the host of a client ID
//   metadata document URL, or the pre-registration; for dynamically registered clients the person confirms it.

import { RESERVED_DELEGATE_LABELS, isDelegateLabel } from "../core/address.ts";
import type { Attestation } from "../core/types.ts";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export interface RedirectPolicy {
  /** Exact hosts (https only). `*` allows any https host. Loopback http is always allowed. */
  hosts: string[];
}

export const DEFAULT_REDIRECT_HOSTS = ["claude.ai", "chatgpt.com"];

export function isLoopbackUri(uri: string): boolean {
  const u = URL.parse(uri);
  return !!u && u.protocol === "http:" && LOOPBACK_HOSTS.has(u.hostname);
}

export function redirectUriPermitted(uri: string, policy: RedirectPolicy): boolean {
  const u = URL.parse(uri);
  if (!u || u.hash || u.username || u.password) return false;
  if (u.protocol === "http:") return LOOPBACK_HOSTS.has(u.hostname);
  if (u.protocol !== "https:") return false;
  return policy.hosts.includes("*") || policy.hosts.includes(u.hostname.toLowerCase());
}

/**
 * The callback URLs the hosted agent platforms publish (bridge-kit/SOURCES.md). A dynamically registered client may use
 * only these, or loopback: any other page on those hosts could leak an authorization code.
 */
export const PUBLISHED_CALLBACKS = ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect"];

export function dcrRedirectAllowed(uri: string): boolean {
  if (isLoopbackUri(uri)) return true;
  const u = URL.parse(uri);
  if (!u) return false;
  // Hosts other than the two platforms are allowed only when the operator added them (redirectUriPermitted decides).
  if (!["claude.ai", "chatgpt.com"].includes(u.hostname.toLowerCase())) return true;
  return PUBLISHED_CALLBACKS.includes(`${u.origin}${u.pathname}`) && !u.search;
}

/** RFC 8252 7.3: a loopback redirect matches a registered one with the port ignored (also for `localhost`, as Claude Code needs). */
export function loopbackMatch(requested: string, registered: string): boolean {
  const a = URL.parse(requested);
  const b = URL.parse(registered);
  if (!a || !b || a.protocol !== "http:" || b.protocol !== "http:") return false;
  if (!LOOPBACK_HOSTS.has(a.hostname) || a.hostname !== b.hostname) return false;
  return a.pathname === b.pathname && a.search === b.search;
}

/** A client_id that is a client ID metadata document URL (CIMD). */
export function isCimdClientId(clientId: string): boolean {
  return /^https:\/\//i.test(clientId);
}

export function slugLabel(input: string | undefined, fallback = "agent"): string {
  const s = (input ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32).replace(/-+$/g, "");
  const label = s && isDelegateLabel(s) && !RESERVED_DELEGATE_LABELS.includes(s) ? s : fallback;
  return label;
}

/** The label a verified client gets: from the CIMD host (claude.ai → claude, chatgpt.com → chatgpt), else its name. */
export function suggestedLabel(clientId: string, clientName: string | undefined): string {
  if (isCimdClientId(clientId)) {
    const host = URL.parse(clientId)?.hostname ?? "";
    const parts = host.split(".").filter(Boolean);
    const core = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    return slugLabel(core, slugLabel(clientName));
  }
  return slugLabel(clientName);
}

/** What the broker can attest about a client before org policy applies (spec 5.4). */
export function clientAttestation(clientId: string): Attestation {
  return isCimdClientId(clientId) ? "vendor" : "self";
}

/**
 * How the consent page names the client: the verified host for CIMD (the document's own name is self-asserted); the
 * registered name for a client the operator pre-registered; otherwise a name marked unverified.
 */
export function clientDisplay(clientId: string, clientName: string | undefined, preRegistered = false): { name: string; verifiedHost?: string } {
  if (isCimdClientId(clientId)) {
    const host = URL.parse(clientId)?.hostname ?? clientId;
    return { name: clientName ? `${clientName.slice(0, 64)} (${host})` : host, verifiedHost: host };
  }
  if (preRegistered) return { name: clientName ? clientName.slice(0, 64) : clientId.slice(0, 64) };
  return { name: clientName ? `${clientName.slice(0, 64)} (unverified name)` : "An unnamed client" };
}
