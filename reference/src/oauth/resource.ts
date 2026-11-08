// SPDX-License-Identifier: FSL-1.1-ALv2
// The protected-resource side of the client binding (spec 5.6; MCP authorization; RFC 6750, 9068, 9728):
// - protected resource metadata for the MCP endpoint and the REST mirror;
// - bearer token verification: JWT access tokens from this broker's authorization server (issuer, audience = the
//   canonical resource URI, `typ: at+jwt`, expiry, the delegate binding), or personal access tokens;
// - the WWW-Authenticate challenges: 401 with `resource_metadata` and `scope` when a token is missing or invalid,
//   403 `insufficient_scope` when the token lacks a scope the tool needs.
// A verified token becomes a DelegateCaller: one principal, one delegate, the client_id.

import { createLocalJWKSet, jwtVerify } from "jose";
import type { JWK } from "jose";
import type { Broker } from "../core/broker.ts";
import { PROTOCOL } from "../core/protocol.ts";
import type { DelegateCaller } from "../core/types.ts";
import { PAT_CLIENT_ID, findPat, looksLikePat } from "./pat.ts";
import { OAUTH_SCOPES } from "./provider.ts";
import type { OAuthScope } from "./provider.ts";
import { StateAdapter } from "./adapter.ts";
import type { BindingStore } from "./state.ts";

export type ResourceKind = "mcp" | "rest";

export interface AuthContext {
  caller: DelegateCaller;
  principal_id: string;
  scopes: OAuthScope[];
  via: "oauth" | "pat";
  resource: ResourceKind;
}

/**
 * What the caller can do about a refused token: `sign_in` (no token was sent), `renew` (refresh it, or create a new
 * personal access token: it is unknown, invalid, expired, revoked, for another resource or for an earlier agent), or
 * `admin` (the person's organization stopped it, or the person isn't active: only an administrator can change that).
 */
export type AuthRemedy = "sign_in" | "renew" | "admin";

export type AuthOutcome =
  | { ok: true; ctx: AuthContext }
  | { ok: false; status: 401; error?: "invalid_token"; description: string; remedy: AuthRemedy };

export interface ResourceGuardOptions {
  broker: Broker;
  state: BindingStore;
  issuer: string;
  /** Canonical resource URIs. */
  resources: Record<ResourceKind, string>;
  /** The authorization server's public signing keys. */
  jwks: { keys: JWK[] };
  /** Reports a refused token (never the token itself). */
  onRefused?: (reason: string, clientId?: string) => void;
}

/** RFC 9728 3.1: the metadata URL for a resource inserts the well-known segment before the resource's path. */
export function metadataUrlFor(resourceUri: string): string {
  const u = new URL(resourceUri);
  const path = u.pathname === "/" ? "" : u.pathname;
  return `${u.origin}/.well-known/oauth-protected-resource${path}`;
}

export function protectedResourceMetadata(resourceUri: string, issuer: string, documentation?: string): Record<string, unknown> {
  return {
    resource: resourceUri,
    authorization_servers: [issuer],
    scopes_supported: [...OAUTH_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: `${PROTOCOL.shortName} broker: client binding`,
    ...(documentation ? { resource_documentation: documentation } : {}),
  };
}

function quote(s: string): string {
  return `"${s.replace(/["\\]/g, "")}"`;
}

/** RFC 6750 3 / RFC 9728 5.1 challenge. */
export function bearerChallenge(args: { resourceMetadata: string; error?: "invalid_token" | "insufficient_scope"; description?: string; scope?: readonly string[] }): string {
  const parts: string[] = [];
  if (args.error) parts.push(`error=${quote(args.error)}`);
  if (args.description) parts.push(`error_description=${quote(args.description)}`);
  parts.push(`resource_metadata=${quote(args.resourceMetadata)}`);
  parts.push(`scope=${quote((args.scope ?? OAUTH_SCOPES).join(" "))}`);
  return `Bearer ${parts.join(", ")}`;
}

export class ResourceGuard {
  private readonly opts: ResourceGuardOptions;
  private readonly keySet: ReturnType<typeof createLocalJWKSet>;

  constructor(opts: ResourceGuardOptions) {
    this.opts = opts;
    this.keySet = createLocalJWKSet(opts.jwks);
  }

  private refuse(description: string, clientId?: string, remedy: AuthRemedy = "renew"): AuthOutcome {
    this.opts.onRefused?.(description, clientId);
    return { ok: false, status: 401, error: "invalid_token", description, remedy };
  }

  /** Verify the Authorization header for one resource. */
  async authenticate(authorization: string | undefined, resource: ResourceKind): Promise<AuthOutcome> {
    if (!authorization) return { ok: false, status: 401, description: "sign-in required", remedy: "sign_in" };
    const m = /^Bearer\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i.exec(authorization);
    if (!m || !m[1]) return this.refuse("malformed Authorization header");
    const token = m[1];
    if (looksLikePat(token)) return this.fromPat(token, resource);
    if (token.split(".").length === 3) return this.fromJwt(token, resource);
    return this.refuse("unknown token");
  }

  private async fromJwt(token: string, resource: ResourceKind): Promise<AuthOutcome> {
    const { broker, issuer, resources } = this.opts;
    let payload: Record<string, unknown>;
    try {
      ({ payload } = await jwtVerify(token, this.keySet, { issuer, audience: resources[resource], typ: "at+jwt", algorithms: ["ES256"], clockTolerance: 5, requiredClaims: ["sub", "exp", "client_id"] }));
    } catch {
      return this.refuse("the access token is invalid, expired or for another resource");
    }
    const sub = payload["sub"];
    const clientId = payload["client_id"];
    const delegateId = payload["alp_delegate"];
    const scope = payload["scope"];
    if (typeof sub !== "string" || typeof clientId !== "string") return this.refuse("the access token is incomplete");
    if (typeof delegateId !== "string") return this.refuse("the access token names no delegate", clientId);
    const principal = await broker.store.getPrincipalById(sub);
    if (!principal || principal.status !== "active") return this.refuse("the principal is not active", clientId, "admin");
    const delegate = await broker.store.getDelegate(delegateId);
    if (!delegate || delegate.status !== "active" || delegate.principal_id !== principal.principal_id || delegate.client_id !== clientId) {
      return this.refuse("the delegate was revoked or no longer matches this client", clientId);
    }
    // Spec 5.4: a connection acts only for the agent binding it was authorized for, never for a later agent given the
    // same name, even when the earlier one was disconnected some other way than the web view (which revokes its
    // connections). Tokens of connections authorized before bindings were recorded carry none.
    const binding = payload["alp_binding"];
    if (typeof binding === "string" && binding !== delegate.created_at) return this.refuse("the connection belongs to an earlier agent with this name", clientId);
    // The token's grant must still exist: refresh-token reuse and code replay revoke it (spec 5.6.7), and so does the
    // person disconnecting the agent, with effect before the token's own expiry.
    const grantId = payload["alp_grant"];
    if (typeof grantId === "string" && !(await new StateAdapter(this.opts.state, "Grant").find(grantId))) return this.refuse("the connection was revoked", clientId);
    if (broker.agentBlocked(principal.address, delegate.id, clientId)) return this.refuse("the organization blocked this agent", clientId, "admin");
    // Spec 6.10: a client the organization's list no longer names (enforce mode) can't read or send, even with a
    // token issued before the list changed.
    if (broker.clientRefused(principal.address, clientId)) return this.refuse("the organization's list of agents doesn't include this agent", clientId, "admin");
    const scopes = (typeof scope === "string" ? scope.split(" ") : []).filter((s): s is OAuthScope => (OAUTH_SCOPES as readonly string[]).includes(s));
    return {
      ok: true,
      ctx: { caller: { kind: "delegate", principal: principal.address, delegate: delegate.id, client_id: clientId }, principal_id: principal.principal_id, scopes, via: "oauth", resource },
    };
  }

  private async fromPat(token: string, resource: ResourceKind): Promise<AuthOutcome> {
    const { broker, state } = this.opts;
    const rec = await findPat(state, token);
    if (!rec) return this.refuse("unknown personal access token", PAT_CLIENT_ID);
    const now = Date.now();
    if (rec.revoked_at || Date.parse(rec.expires_at) <= now) return this.refuse("the personal access token was revoked or has expired", PAT_CLIENT_ID);
    const principal = await broker.store.getPrincipalById(rec.principal_id);
    if (!principal || principal.status !== "active") return this.refuse("the principal is not active", PAT_CLIENT_ID, "admin");
    const delegate = await broker.store.getDelegate(rec.delegate);
    if (!delegate || delegate.status !== "active" || delegate.principal_id !== principal.principal_id || delegate.client_id !== PAT_CLIENT_ID) {
      return this.refuse("the delegate was revoked", PAT_CLIENT_ID);
    }
    // Spec 5.4: a token minted for an earlier agent with this name never acts for a later one, even when the earlier
    // one was disconnected some other way than the web view (which revokes its tokens).
    if (rec.binding !== undefined && rec.binding !== delegate.created_at) return this.refuse("the personal access token belongs to an earlier agent with this name", PAT_CLIENT_ID);
    if (broker.agentBlocked(principal.address, delegate.id, PAT_CLIENT_ID)) return this.refuse("the organization blocked this agent", PAT_CLIENT_ID, "admin");
    // Spec 5.7, 6.10: leaving `pat` off the list (enforce mode) forbids personal access tokens, those already issued too.
    if (broker.clientRefused(principal.address, PAT_CLIENT_ID)) return this.refuse("the organization doesn't allow personal access tokens", PAT_CLIENT_ID, "admin");
    // The use is noted at most once a minute, and only on a token that is still live: one revoked since it was read
    // above stays revoked, and this request is refused.
    if (!rec.last_used_at || now - Date.parse(rec.last_used_at) > 60_000) {
      if (!(await state.touchPat(rec.id, new Date(now).toISOString()))) return this.refuse("the personal access token was revoked or has expired", PAT_CLIENT_ID);
    }
    return {
      ok: true,
      ctx: { caller: { kind: "delegate", principal: principal.address, delegate: delegate.id, client_id: PAT_CLIENT_ID }, principal_id: principal.principal_id, scopes: [...rec.scopes], via: "pat", resource },
    };
  }
}
