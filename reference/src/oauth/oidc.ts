// SPDX-License-Identifier: FSL-1.1-ALv2
// OpenID Connect sign-in (spec 5.2, 5.3, 12.5.2): the broker as a relying party of the organization's identity
// provider. Agents never see this. They register with the broker's own authorization server (provider.ts), whose
// sign-in step (interaction.ts), like the person's web view (web/app.ts), hands the person to the provider here.
//
// - The authorization code flow with PKCE (S256), `state` and `nonce`. The broker is a confidential client of the
//   provider (a client secret, sent with client_secret_basic or client_secret_post).
// - Discovery, the provider's key set and its token endpoint are fetched through the hardened fetcher (spec 4.3):
//   https on port 443, public addresses only, no redirects, size and time caps.
// - The ID token: a signature from the provider's key set (asymmetric algorithms only), the exact issuer, the broker
//   as its only audience (and `azp`, when present), expiry and `iat` with a small clock skew, the nonce, and
//   `auth_time` when a fresh sign-in was asked for.
// - Microsoft Entra ID: the per-tenant issuer https://login.microsoftonline.com/<tenant-id>/v2.0, for a single-tenant
//   or a multi-tenant ("organizations") app. A token from a tenant the configuration doesn't list is refused. Both
//   token requests name the scopes again, as Entra's v2.0 endpoint may require.
// - The principal binds to iss + sub (Entra: the tenant's issuer, which names `tid`, + `oid`), never to email,
//   preferred_username or upn (spec 5.2). The address is only an alias, read from a configured claim, and must be on
//   a domain this provider (or this tenant) may sign people in for.
// - Group or app-role claims become the principal's claims, which the policy's claim-based groups match (spec 6.4).
//   An overflowed group claim (Entra's "groups overage", where the token carries a link instead of the list) refuses
//   the sign-in: the broker never signs someone in with groups it can't see.

import { createHash, randomBytes } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, errors as joseErrors, jwtVerify } from "jose";
import type { JSONWebKeySet, JWK, JWTPayload } from "jose";
import { domainOf, parseAddress } from "../core/address.ts";
import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import { AlpError, errMessage } from "../core/errors.ts";
import type { IdentityAssertion, IdentityVerifier, VerifiedIdentity } from "../core/interfaces.ts";
import type { Address } from "../core/types.ts";
import { FetchFailure, isJsonContentType } from "../federation/fetcher.ts";
import type { HardenedFetcher, HttpResponse } from "../federation/fetcher.ts";
import { parseStrictJsonBytes } from "../federation/strict-json.ts";

/** Asymmetric signature algorithms only: never `none`, and never HMAC with the client secret. */
export const ID_TOKEN_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"] as const;

/** Microsoft Entra ID's public cloud authority (sovereign clouds use their own, set with `authority`). */
export const ENTRA_AUTHORITY = "https://login.microsoftonline.com";

/** An ID token from a code exchange must be this recent (seconds, plus the clock skew). */
const MAX_ID_TOKEN_AGE = 600;
const DISCOVERY_TTL_MS = 3600_000;
/** A discovery document that can't be refreshed is used for at most this long. */
const DISCOVERY_STALE_MS = 24 * 3600_000;
const JWKS_TTL_MS = 3600_000;
/** An unknown key id refetches the key set, at most once a minute. */
const JWKS_REFETCH_MS = 60_000;
const MAX_GROUP_VALUES = 1000;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type OidcProviderKind = "generic" | "entra";

/** The validated OIDC configuration (from `identity` in the broker's configuration; see parseOidcConfig). */
export interface OidcSettings {
  provider: OidcProviderKind;
  /** The issuer ID tokens carry. A multi-tenant Entra app: the template `<authority>/{tenantid}/v2.0`. */
  issuer: string;
  /** Where the provider's discovery document is. */
  discoveryUrl: string;
  /** Entra: the authority (`https://login.microsoftonline.com`), from which each tenant's issuer is built. */
  authority?: string;
  /** Entra: each tenant whose people may sign in, with the domains its people may hold addresses on. */
  tenants?: Readonly<Record<string, readonly string[]>>;
  /** Generic: the domains this provider's people may hold addresses on. */
  domains: readonly string[];
  clientId: string;
  clientAuth: "client_secret_basic" | "client_secret_post";
  scopes: readonly string[];
  /** The claim the address alias comes from. Never the binding. */
  addressClaim: string;
  /** With `address_claim: "email"`, only a verified email (`email_verified: true`) is an address. */
  requireVerifiedEmail: boolean;
  /** Claims whose values become the principal's group claims (Entra: `roles`, or `groups`). */
  groupClaims: readonly string[];
  /** Re-check the person at the provider whenever their agent's connection refreshes (the provider's refresh token). */
  refreshCheck: boolean;
  /** Entra: sign in guest accounts too (an `idp` claim other than the issuer). Default false: members only. */
  allowGuests: boolean;
  /** Connector sign-ins ask the provider for a fresh sign-in (`prompt=login`). */
  freshSignIn: boolean;
  clockSkewSeconds: number;
}

function fail(path: string, why: string): never {
  throw new Error(`identity.${path}: ${why}`);
}

function httpsOrigin(value: unknown, path: string): string {
  if (typeof value !== "string") fail(path, "must be an https origin");
  const u = URL.parse(value);
  if (!u || u.protocol !== "https:" || u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) fail(path, "must be an https origin, such as https://login.microsoftonline.com");
  return u.origin;
}

function stringList(value: unknown, path: string, opts: { min?: number; max?: number } = {}): string[] {
  if (!Array.isArray(value) || !value.every((x) => typeof x === "string" && x.length > 0 && x.length <= 256)) fail(path, "must be a list of strings");
  if (value.length < (opts.min ?? 0) || value.length > (opts.max ?? 50)) fail(path, `must list ${opts.min ?? 0} to ${opts.max ?? 50} values`);
  return [...value] as string[];
}

function hostedDomains(value: unknown, path: string, brokerDomains: readonly string[]): string[] {
  const list = stringList(value, path, { min: 1 }).map((d) => d.toLowerCase());
  for (const d of list) if (!brokerDomains.includes(d)) fail(path, `${d} is not one of the broker's domains`);
  return list;
}

const KNOWN_KEYS = new Set([
  "kind", "provider", "issuer", "tenant", "tenants", "authority", "client_id", "client_auth", "scopes", "address_claim",
  "require_verified_email", "group_claims", "refresh_check", "fresh_sign_in", "clock_skew_seconds", "domains", "allow_guests",
]);

/**
 * Validates the `identity` block of the broker's configuration for `kind: "oidc"`. The client secret is never in
 * the file: main.ts reads it from ALP_OIDC_CLIENT_SECRET.
 */
export function parseOidcConfig(raw: unknown, brokerDomains: readonly string[]): OidcSettings {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) fail("", "must be an object");
  const c = raw as Record<string, unknown>;
  if (c["kind"] !== "oidc") fail("kind", 'must be "oidc"');
  if ("client_secret" in c) fail("client_secret", "never goes in the file: set ALP_OIDC_CLIENT_SECRET");
  for (const k of Object.keys(c)) if (!KNOWN_KEYS.has(k)) fail(k, "is not a setting (check the spelling; SELF-HOST.md lists them)");
  const provider = c["provider"] ?? "generic";
  if (provider !== "generic" && provider !== "entra") fail("provider", 'must be "generic" or "entra"');
  const clientId = c["client_id"];
  if (typeof clientId !== "string" || clientId.length < 1 || clientId.length > 256) fail("client_id", "is required: the broker's client id at the identity provider");
  const clientAuth = c["client_auth"] ?? (provider === "entra" ? "client_secret_post" : "client_secret_basic");
  if (clientAuth !== "client_secret_basic" && clientAuth !== "client_secret_post") fail("client_auth", 'must be "client_secret_basic" or "client_secret_post"');
  const refreshCheck = c["refresh_check"] ?? true;
  if (typeof refreshCheck !== "boolean") fail("refresh_check", "must be true or false");
  const freshSignIn = c["fresh_sign_in"] ?? true;
  if (typeof freshSignIn !== "boolean") fail("fresh_sign_in", "must be true or false");
  const skew = c["clock_skew_seconds"] ?? 60;
  if (typeof skew !== "number" || !Number.isInteger(skew) || skew < 0 || skew > 300) fail("clock_skew_seconds", "must be 0 to 300");
  const scopes = c["scopes"] !== undefined ? stringList(c["scopes"], "scopes", { min: 1, max: 20 }) : ["openid", "profile", "email"];
  if (!scopes.includes("openid")) fail("scopes", 'must include "openid"');
  if (provider === "entra" && !scopes.includes("profile")) fail("scopes", 'must include "profile" for provider "entra": Entra sends oid (the binding) and preferred_username only with it');
  if (refreshCheck && !scopes.includes("offline_access")) scopes.push("offline_access");
  const addressClaim = c["address_claim"] ?? (provider === "entra" ? "preferred_username" : "email");
  if (typeof addressClaim !== "string" || !/^[A-Za-z0-9_.:-]{1,64}$/.test(addressClaim)) fail("address_claim", "must be a claim name");
  for (const forbidden of ["sub", "oid", "tid"]) if (addressClaim === forbidden) fail("address_claim", `can't be ${forbidden}: the address is an alias, not the binding`);
  const requireVerifiedEmail = c["require_verified_email"] ?? (provider === "generic" && addressClaim === "email");
  if (typeof requireVerifiedEmail !== "boolean") fail("require_verified_email", "must be true or false");
  const groupClaims = c["group_claims"] !== undefined ? stringList(c["group_claims"], "group_claims", { max: 4 }) : [provider === "entra" ? "roles" : "groups"];
  for (const g of groupClaims) if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(g)) fail("group_claims", `${g} is not a claim name`);
  const allowGuests = c["allow_guests"] ?? false;
  if (typeof allowGuests !== "boolean") fail("allow_guests", "must be true or false");
  const common = { clientId, clientAuth, scopes, addressClaim, requireVerifiedEmail, groupClaims, refreshCheck, freshSignIn, allowGuests, clockSkewSeconds: skew } as const;

  if (provider === "generic") {
    for (const k of ["tenant", "tenants", "authority", "allow_guests"]) if (k in c) fail(k, 'applies only to provider "entra"');
    const issuer = c["issuer"];
    const u = typeof issuer === "string" ? URL.parse(issuer) : null;
    if (!u || u.protocol !== "https:" || u.search || u.hash || u.username || u.password) fail("issuer", "must be the provider's https issuer, exactly as its ID tokens carry it");
    const domains = c["domains"] !== undefined ? hostedDomains(c["domains"], "domains", brokerDomains) : [...brokerDomains];
    // OpenID Connect Discovery 1.0, section 4: a trailing slash is removed before the well-known path is appended.
    return { provider, issuer: issuer as string, discoveryUrl: `${(issuer as string).replace(/\/$/, "")}/.well-known/openid-configuration`, domains, ...common };
  }

  if ("issuer" in c) fail("issuer", 'is derived from "tenant" for provider "entra"');
  if ("domains" in c) fail("domains", 'for provider "entra", list domains per tenant in "tenants"');
  const authority = c["authority"] !== undefined ? httpsOrigin(c["authority"], "authority") : ENTRA_AUTHORITY;
  const tenant = typeof c["tenant"] === "string" ? c["tenant"].toLowerCase() : undefined;
  if (tenant === undefined || (tenant !== "organizations" && !GUID.test(tenant))) fail("tenant", 'must be your tenant id (a GUID), or "organizations" for a multi-tenant app');
  const tenants: Record<string, string[]> = {};
  if (c["tenants"] !== undefined) {
    const t = c["tenants"];
    if (typeof t !== "object" || t === null || Array.isArray(t)) fail("tenants", "must map tenant ids to lists of domains");
    for (const [tid, domains] of Object.entries(t)) {
      if (!GUID.test(tid.toLowerCase())) fail(`tenants.${tid}`, "is not a tenant id");
      tenants[tid.toLowerCase()] = hostedDomains(domains, `tenants.${tid}`, brokerDomains);
    }
  }
  if (tenant === "organizations") {
    if (Object.keys(tenants).length === 0) fail("tenants", 'is required with "organizations": list each tenant whose people may sign in, and its domains');
  } else {
    for (const tid of Object.keys(tenants)) if (tid !== tenant) fail(`tenants.${tid}`, "a single-tenant app accepts only its own tenant (use \"organizations\" for several)");
    tenants[tenant] ??= [...brokerDomains];
  }
  const issuer = tenant === "organizations" ? `${authority}/{tenantid}/v2.0` : `${authority}/${tenant}/v2.0`;
  return { provider, issuer, discoveryUrl: `${authority}/${tenant}/v2.0/.well-known/openid-configuration`, authority, tenants, domains: [...new Set(Object.values(tenants).flat())], ...common };
}

// ---------------------------------------------------------------------------------------------
// Errors

export type OidcRefusal =
  | "stale" | "idp_unavailable" | "idp_refused" | "bad_response" | "bad_token" | "bad_signature" | "wrong_issuer" | "wrong_audience"
  | "bad_nonce" | "expired" | "not_fresh" | "wrong_tenant" | "wrong_subject" | "missing_claim" | "no_address"
  | "address_not_allowed" | "email_not_verified" | "groups_overage" | "no_refresh_token" | "rate_limited" | "guest_account";

const PERSON_TEXT: Record<OidcRefusal, string> = {
  stale: "This sign-in has expired, was already used, or was started in another browser.",
  no_refresh_token:
    "Your organization's sign-in service didn't let the broker re-check your account later, which this broker requires for connected agents. Ask your administrator to allow offline access (the offline_access permission) for the broker's application.",
  rate_limited: "Too many sign-ins were started from here. Wait a few minutes and try again.",
  guest_account: "Your account is a guest in your organization's directory. This broker signs in only the organization's own members.",
  idp_unavailable: "Your organization's sign-in service couldn't be reached. Try again in a few minutes.",
  idp_refused: "Your organization's sign-in service didn't complete the sign-in.",
  bad_response: "Your organization's sign-in service sent an answer the broker can't use.",
  bad_token: "The sign-in couldn't be verified.",
  bad_signature: "The sign-in couldn't be verified: its signature doesn't check out.",
  wrong_issuer: "The sign-in came from an identity provider this broker doesn't trust.",
  wrong_audience: "The sign-in was issued for another application.",
  bad_nonce: "The sign-in doesn't belong to this request.",
  expired: "The sign-in has expired.",
  not_fresh: "The broker asked your organization's sign-in service to confirm it's you again, and it didn't.",
  wrong_tenant: "Your account belongs to an organization this broker doesn't serve.",
  wrong_subject: "You signed in as someone other than the person this page belongs to.",
  missing_claim: "The sign-in is missing information the broker needs. Ask your administrator to check the broker's application at your identity provider.",
  no_address: "Your account has no address the broker can use. Ask your administrator.",
  address_not_allowed: "Your account's address isn't on a domain this broker serves for your organization.",
  email_not_verified: "Your identity provider hasn't verified your email address.",
  groups_overage:
    "Your account is in more groups than your organization's sign-in service lists in a sign-in, so the broker can't see which of them you're in, and it doesn't sign anyone in with groups it can't see. Ask your administrator to use app roles (recommended), or to send only the groups assigned to the broker's application.",
};

/** A refused OIDC sign-in. `reason` is safe to show; `detail` is for the operator's log only. */
export class OidcSignInError extends Error {
  readonly reason: OidcRefusal;
  readonly detail: string;
  /** The provider's own OAuth error code, when it sent one. */
  readonly idpError: string | undefined;

  constructor(reason: OidcRefusal, detail: string, idpError?: string) {
    super(`${reason}: ${detail}`);
    this.name = "OidcSignInError";
    this.reason = reason;
    this.detail = detail;
    this.idpError = idpError;
  }

  /** What the person sees (never the provider's error text). */
  get personText(): string {
    return PERSON_TEXT[this.reason];
  }
}

export function isOidcSignInError(err: unknown): err is OidcSignInError {
  return err instanceof OidcSignInError;
}

/**
 * Token endpoint errors that refuse the person: their grant was revoked or expired, their account disabled or deleted,
 * or the provider wants them to sign in again (RFC 6749 5.2; OpenID Connect Core 3.1.2.6; Entra answers
 * interaction_required at its token endpoint too). The others (the broker's client credentials rejected, a request the
 * provider can't take, a grant or scope it doesn't allow) are the broker's own problem.
 */
const PERSON_REFUSALS: ReadonlySet<string> = new Set(["invalid_grant", "interaction_required", "login_required", "consent_required", "access_denied"]);

/** Whether the provider's token endpoint refused the person (not the broker's own request). */
export function refusesPerson(err: OidcSignInError): boolean {
  return err.reason === "idp_refused" && err.idpError !== undefined && PERSON_REFUSALS.has(err.idpError);
}

// ---------------------------------------------------------------------------------------------
// The relying party

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  /** RFC 9207: the provider puts `iss` in its authorization responses. */
  iss_parameter: boolean;
}

/** What the ID token must show besides signature, issuer and audience. */
export interface IdTokenExpectations {
  /** The nonce sent with the authorization request. */
  nonce?: string;
  /** For a refreshed ID token: a nonce, if present, must be the original one (OpenID Connect Core 12.2). */
  nonceOptional?: boolean;
  /** Epoch seconds the sign-in started: `auth_time`, when present, must not be earlier (a fresh sign-in was asked for). */
  freshSince?: number;
  /** `auth_time` must be present (a step-up). */
  requireAuthTime?: boolean;
  /** A code exchange's ID token is recent; a refreshed one is checked only for expiry. */
  checkAge?: boolean;
}

/** A verified OIDC identity: the binding (iss + sub; Entra: the tenant's issuer + oid), the address alias and claims. */
export interface OidcIdentity extends VerifiedIdentity {
  method: "oidc";
  claims: { issuer: string; name: string; value: string }[];
  /** Epoch seconds the person last authenticated at the provider, when the token says. */
  auth_time?: number;
  amr?: string[];
  /** Entra: the tenant id. */
  tenant?: string;
}

export interface OidcRelyingPartyOptions {
  settings: OidcSettings;
  /** The broker's client secret at the provider (ALP_OIDC_CLIENT_SECRET). Never logged. */
  clientSecret: string;
  fetcher: HardenedFetcher;
  clock?: Clock;
  log?: (line: string) => void;
}

export function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

export function randomToken(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

export function pkceChallenge(verifier: string): string {
  return base64url(createHash("sha256").update(verifier, "ascii").digest());
}

/** application/x-www-form-urlencoded, for the client id and secret in an HTTP Basic header (RFC 6749 2.3.1). */
function formEncode(s: string): string {
  return new URLSearchParams({ v: s }).toString().slice(2);
}

function isHttpsUrl(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const u = URL.parse(v);
  return !!u && u.protocol === "https:" && !u.username && !u.password && !u.hash;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class OidcRelyingParty implements IdentityVerifier {
  readonly id: string;
  readonly settings: OidcSettings;
  private readonly secret: string;
  private readonly fetcher: HardenedFetcher;
  private readonly clock: Clock;
  private readonly log: (line: string) => void;
  private disco: { doc: Discovery; at: number } | undefined;
  private discoInFlight: Promise<Discovery> | undefined;
  private keySet: { jwks: JSONWebKeySet; at: number } | undefined;
  private keysInFlight: Promise<JSONWebKeySet> | undefined;

  constructor(opts: OidcRelyingPartyOptions) {
    if (!opts.clientSecret) throw new Error("the OIDC client secret is empty (set ALP_OIDC_CLIENT_SECRET)");
    this.settings = opts.settings;
    this.secret = opts.clientSecret;
    this.fetcher = opts.fetcher;
    this.clock = opts.clock ?? systemClock;
    this.log = opts.log ?? (() => undefined);
    this.id = `oidc:${opts.settings.issuer}`;
  }

  // ---- discovery and keys

  /** The provider's discovery document, cached for an hour (an older copy is used for up to a day if a refresh fails). */
  async discovery(): Promise<Discovery> {
    const now = Date.now();
    if (this.disco && now - this.disco.at < DISCOVERY_TTL_MS) return this.disco.doc;
    this.discoInFlight ??= this.fetchDiscovery().finally(() => {
      this.discoInFlight = undefined;
    });
    try {
      const doc = await this.discoInFlight;
      this.disco = { doc, at: Date.now() };
      return doc;
    } catch (err) {
      if (this.disco && now - this.disco.at < DISCOVERY_STALE_MS) {
        this.log(`oidc: kept the cached discovery document (refresh failed: ${errMessage(err)})`);
        return this.disco.doc;
      }
      throw err;
    }
  }

  private async fetchDiscovery(): Promise<Discovery> {
    let raw: unknown;
    try {
      raw = await this.fetcher.getJson(this.settings.discoveryUrl);
    } catch (err) {
      throw new OidcSignInError("idp_unavailable", `discovery document: ${errMessage(err)}`);
    }
    if (!isObject(raw)) throw new OidcSignInError("bad_response", "the discovery document is not a JSON object");
    if (raw["issuer"] !== this.settings.issuer) throw new OidcSignInError("wrong_issuer", `the discovery document names issuer ${JSON.stringify(String(raw["issuer"]).slice(0, 200))}, not ${this.settings.issuer}`);
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
      if (!isHttpsUrl(raw[k])) throw new OidcSignInError("bad_response", `the discovery document's ${k} is not an https URL`);
    }
    if (raw["end_session_endpoint"] !== undefined && !isHttpsUrl(raw["end_session_endpoint"])) throw new OidcSignInError("bad_response", "end_session_endpoint is not an https URL");
    const algs = raw["id_token_signing_alg_values_supported"];
    if (Array.isArray(algs) && !algs.some((a) => (ID_TOKEN_ALGORITHMS as readonly unknown[]).includes(a))) {
      throw new OidcSignInError("bad_response", "the provider signs ID tokens with no algorithm this broker accepts (asymmetric only)");
    }
    return {
      issuer: raw["issuer"] as string,
      authorization_endpoint: raw["authorization_endpoint"] as string,
      token_endpoint: raw["token_endpoint"] as string,
      jwks_uri: raw["jwks_uri"] as string,
      ...(typeof raw["end_session_endpoint"] === "string" ? { end_session_endpoint: raw["end_session_endpoint"] } : {}),
      iss_parameter: raw["authorization_response_iss_parameter_supported"] === true,
    };
  }

  /** The provider's signing keys (public, signature keys only), cached for an hour; `refresh` refetches at most once a minute. */
  private async keys(refresh = false): Promise<JSONWebKeySet> {
    const now = Date.now();
    const cached = this.keySet;
    if (cached && !refresh && now - cached.at < JWKS_TTL_MS) return cached.jwks;
    if (cached && refresh && now - cached.at < JWKS_REFETCH_MS) return cached.jwks;
    this.keysInFlight ??= this.fetchKeys().finally(() => {
      this.keysInFlight = undefined;
    });
    const jwks = await this.keysInFlight;
    this.keySet = { jwks, at: Date.now() };
    return jwks;
  }

  private async fetchKeys(): Promise<JSONWebKeySet> {
    const { jwks_uri } = await this.discovery();
    let raw: unknown;
    try {
      raw = await this.fetcher.getJson(jwks_uri);
    } catch (err) {
      throw new OidcSignInError("idp_unavailable", `key set: ${errMessage(err)}`);
    }
    if (!isObject(raw) || !Array.isArray(raw["keys"])) throw new OidcSignInError("bad_response", "the key set has no keys");
    const keys: JWK[] = [];
    for (const k of raw["keys"].slice(0, 100)) {
      if (!isObject(k)) continue;
      // Public signature keys only: no symmetric keys, nothing with private members, nothing marked for encryption.
      if (k["kty"] !== "RSA" && k["kty"] !== "EC" && k["kty"] !== "OKP") continue;
      if (k["use"] !== undefined && k["use"] !== "sig") continue;
      if (["d", "p", "q", "dp", "dq", "qi", "k"].some((m) => m in k)) continue;
      keys.push(k as JWK);
    }
    if (keys.length === 0) throw new OidcSignInError("bad_response", "the key set has no usable signature keys");
    return { keys };
  }

  // ---- the authorization request

  /** The provider's authorization URL for one sign-in. The caller keeps `state`, `nonce` and the code verifier. */
  async authorizationUrl(args: { redirectUri: string; state: string; nonce: string; codeVerifier: string; prompt?: "login"; maxAge?: number; loginHint?: string }): Promise<string> {
    const d = await this.discovery();
    const u = new URL(d.authorization_endpoint);
    const p = u.searchParams;
    p.set("response_type", "code");
    p.set("client_id", this.settings.clientId);
    p.set("redirect_uri", args.redirectUri);
    p.set("scope", this.settings.scopes.join(" "));
    p.set("state", args.state);
    p.set("nonce", args.nonce);
    p.set("code_challenge", pkceChallenge(args.codeVerifier));
    p.set("code_challenge_method", "S256");
    if (args.prompt) p.set("prompt", args.prompt);
    if (args.maxAge !== undefined) p.set("max_age", String(args.maxAge));
    if (args.loginHint) p.set("login_hint", args.loginHint);
    return u.href;
  }

  /**
   * RFC 9207: the `iss` of an authorization response, checked before the code is used (mix-up defense). Required
   * when the provider says it sends one.
   */
  async checkResponseIssuer(iss: string | undefined): Promise<void> {
    const d = await this.discovery();
    if (iss === undefined) {
      if (d.iss_parameter) throw new OidcSignInError("wrong_issuer", "the authorization response has no iss, though the provider says it sends one");
      return;
    }
    if (this.settings.provider === "entra" ? this.entraTenantOf(iss) === null : iss !== this.settings.issuer) {
      throw new OidcSignInError("wrong_issuer", "the authorization response came from another issuer");
    }
  }

  // ---- the token endpoint

  private async tokenRequest(params: Record<string, string>): Promise<Record<string, unknown>> {
    const d = await this.discovery();
    const body = new URLSearchParams(params);
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json", "cache-control": "no-store" };
    if (this.settings.clientAuth === "client_secret_basic") {
      headers["authorization"] = `Basic ${Buffer.from(`${formEncode(this.settings.clientId)}:${formEncode(this.secret)}`).toString("base64")}`;
    } else {
      body.set("client_id", this.settings.clientId);
      body.set("client_secret", this.secret);
    }
    let res: HttpResponse;
    try {
      res = await this.fetcher.request(d.token_endpoint, { method: "POST", headers, body: Buffer.from(body.toString(), "utf8") });
    } catch (err) {
      throw new OidcSignInError("idp_unavailable", `token endpoint: ${err instanceof FetchFailure ? err.message : errMessage(err)}`);
    }
    let json: unknown;
    if (isJsonContentType(res.headers["content-type"])) {
      try {
        json = parseStrictJsonBytes(res.body);
      } catch {
        json = undefined;
      }
    }
    if (res.status === 200) {
      if (!isObject(json)) throw new OidcSignInError("bad_response", "the token response is not a JSON object");
      return json;
    }
    const error = isObject(json) && typeof json["error"] === "string" ? json["error"].slice(0, 64) : undefined;
    // Entra also names its own error codes (AADSTS<number>): the operator's log shows them, the person never does.
    const codes = this.settings.provider === "entra" && isObject(json) && Array.isArray(json["error_codes"]) ? json["error_codes"].filter((c): c is number => Number.isInteger(c)).slice(0, 3) : [];
    const detail = `token endpoint answered HTTP ${res.status}${error ? ` ${error}` : ""}${codes.length ? ` (${codes.map((c) => `AADSTS${c}`).join(", ")})` : ""}`;
    // Throttling (429) and the errors that say the provider is busy or failing (Entra answers temporarily_unavailable
    // when it is too busy) mean it is unavailable, as a 5xx does: not a refusal.
    if (res.status >= 400 && res.status < 500 && res.status !== 429 && error && error !== "temporarily_unavailable" && error !== "server_error") throw new OidcSignInError("idp_refused", detail, error);
    throw new OidcSignInError("idp_unavailable", detail, error);
  }

  /**
   * Microsoft Entra: both token requests name the configured scopes again. Its v2.0 token endpoint documents `scope`
   * there as optional, but has been reported to refuse a request without it (AADSTS900144), and it returns an ID token
   * from a refresh only when `openid` is asked for. Other providers get none (RFC 6749 6: the grant's own scopes).
   */
  private tokenScope(): Record<string, string> {
    return this.settings.provider === "entra" ? { scope: this.settings.scopes.join(" ") } : {};
  }

  /** Exchanges an authorization code (with its PKCE verifier) and verifies the ID token. */
  async signIn(args: { code: string; redirectUri: string; codeVerifier: string; nonce: string; freshSince?: number; requireAuthTime?: boolean }): Promise<{ identity: OidcIdentity; refreshToken?: string }> {
    const json = await this.tokenRequest({ grant_type: "authorization_code", code: args.code, redirect_uri: args.redirectUri, code_verifier: args.codeVerifier, ...this.tokenScope() });
    const idToken = json["id_token"];
    if (typeof idToken !== "string") throw new OidcSignInError("bad_response", "the token response has no ID token");
    const claims = await this.validateIdToken(idToken, {
      nonce: args.nonce,
      checkAge: true,
      ...(args.freshSince !== undefined ? { freshSince: args.freshSince } : {}),
      ...(args.requireAuthTime ? { requireAuthTime: true } : {}),
    });
    const identity = this.identityFrom(claims);
    const rt = json["refresh_token"];
    return { identity, ...(typeof rt === "string" && rt.length > 0 && rt.length <= 8192 ? { refreshToken: rt } : {}) };
  }

  /**
   * Re-checks the person at the provider with its refresh token. The provider refuses (`idp_refused`) when the
   * account was disabled or deleted, or its sessions revoked. A new ID token, when the provider sends one, must
   * name the same person, and gives the current group claims.
   *
   * The provider accepting the refresh token is the re-check. An ID token it sends with it that isn't signed with an
   * accepted algorithm by one of its keys (Microsoft documents Entra's refreshed ID token as unsigned) is left unused,
   * and the person's group claims stay as they were; a signed one for another issuer, audience or person refuses.
   */
  async refresh(refreshToken: string, expect: { iss: string; sub: string; nonce?: string }): Promise<{ groups?: OidcIdentity["claims"]; refreshToken?: string }> {
    const json = await this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken, ...this.tokenScope() });
    let groups: OidcIdentity["claims"] | undefined;
    const idToken = json["id_token"];
    if (typeof idToken === "string") {
      let claims: JWTPayload | undefined;
      try {
        claims = await this.validateIdToken(idToken, { ...(expect.nonce !== undefined ? { nonce: expect.nonce } : {}), nonceOptional: true });
      } catch (err) {
        if (!isOidcSignInError(err) || (err.reason !== "bad_signature" && err.reason !== "bad_token")) throw err;
        this.log(`oidc: left a refresh's ID token unused (${err.reason}: ${err.detail}); the person's group claims stay as they were`);
      }
      if (claims) {
        const binding = this.bindingOf(claims);
        if (binding.iss !== expect.iss || binding.sub !== expect.sub) throw new OidcSignInError("wrong_subject", "the refreshed ID token names another person");
        groups = this.groupsOf(claims, binding.iss);
      }
    }
    const rt = json["refresh_token"];
    return { ...(groups ? { groups } : {}), ...(typeof rt === "string" && rt.length > 0 && rt.length <= 8192 ? { refreshToken: rt } : {}) };
  }

  /** RP-initiated logout at the provider, when it offers it: where to send the browser after the broker's own sign-out. */
  async endSessionUrl(postLogoutRedirectUri: string): Promise<string | null> {
    let d: Discovery;
    try {
      d = await this.discovery();
    } catch {
      return null;
    }
    if (!d.end_session_endpoint) return null;
    const u = new URL(d.end_session_endpoint);
    u.searchParams.set("client_id", this.settings.clientId);
    u.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
    return u.href;
  }

  // ---- the ID token

  /** Entra: the tenant id an issuer names, if it is the authority's v2.0 issuer for a listed tenant, else null. */
  private entraTenantOf(iss: string): string | null {
    const prefix = `${this.settings.authority ?? ENTRA_AUTHORITY}/`;
    if (!iss.startsWith(prefix) || !iss.endsWith("/v2.0")) return null;
    const tid = iss.slice(prefix.length, -"/v2.0".length);
    return GUID.test(tid) && this.settings.tenants?.[tid] ? tid : null;
  }

  /** Signature, issuer, audience, expiry, `iat`, nonce and `auth_time`, in that order. Returns the claims. */
  async validateIdToken(idToken: string, expect: IdTokenExpectations): Promise<JWTPayload> {
    const s = this.settings;
    let header;
    try {
      header = decodeProtectedHeader(idToken);
    } catch {
      throw new OidcSignInError("bad_token", "the ID token is not a signed JWT");
    }
    if (typeof header.alg !== "string" || !(ID_TOKEN_ALGORITHMS as readonly string[]).includes(header.alg)) throw new OidcSignInError("bad_signature", `ID token algorithm ${JSON.stringify(header.alg)} is not accepted`);
    if (header.typ !== undefined && String(header.typ).toLowerCase() !== "jwt") throw new OidcSignInError("bad_token", `ID token type ${JSON.stringify(header.typ)}`);
    const now = this.clock.now();
    const verify = async (jwks: JSONWebKeySet): Promise<JWTPayload> =>
      (await jwtVerify(idToken, createLocalJWKSet(jwks), { algorithms: [...ID_TOKEN_ALGORITHMS], clockTolerance: s.clockSkewSeconds, currentDate: now, requiredClaims: ["iss", "sub", "aud", "exp", "iat"] })).payload;
    let claims: JWTPayload;
    try {
      claims = await verify(await this.keys());
    } catch (err) {
      if (!(err instanceof joseErrors.JWKSNoMatchingKey)) throw joseFailure(err);
      // The provider may have rotated its keys: refetch once (at most once a minute) and try again.
      try {
        claims = await verify(await this.keys(true));
      } catch (again) {
        throw joseFailure(again);
      }
    }
    const nowSec = Math.floor(now.getTime() / 1000);

    // Issuer: exactly the configured one; for Entra, the issuer of a listed tenant, matching the token's `tid`.
    const iss = String(claims.iss);
    if (s.provider === "entra") {
      const prefix = `${s.authority ?? ENTRA_AUTHORITY}/`;
      const tid = claims["tid"];
      if (typeof tid !== "string" || !GUID.test(tid)) throw new OidcSignInError("missing_claim", "the ID token has no tid");
      if (iss !== `${prefix}${tid}/v2.0`) throw new OidcSignInError("wrong_issuer", "the ID token's issuer is not the v2.0 issuer of its own tenant");
      if (this.entraTenantOf(iss) === null) throw new OidcSignInError("wrong_tenant", `tenant ${tid} is not configured`);
    } else if (iss !== s.issuer) {
      throw new OidcSignInError("wrong_issuer", "the ID token's issuer is not the configured issuer");
    }

    // Audience: the broker's client id, alone; `azp`, when present, the same.
    const aud = claims.aud;
    const auds = Array.isArray(aud) ? aud : [aud];
    if (auds.length !== 1 || auds[0] !== s.clientId) throw new OidcSignInError("wrong_audience", "the ID token is not for this broker alone");
    if (claims["azp"] !== undefined && claims["azp"] !== s.clientId) throw new OidcSignInError("wrong_audience", "the ID token's azp is another client");

    // `iat`: not in the future; a code exchange's token is recent.
    const iat = claims.iat as number;
    if (iat > nowSec + s.clockSkewSeconds) throw new OidcSignInError("bad_token", "the ID token was issued in the future");
    if (expect.checkAge && nowSec - iat > MAX_ID_TOKEN_AGE + s.clockSkewSeconds) throw new OidcSignInError("expired", "the ID token is too old");

    // Nonce: the one this sign-in sent (a refreshed token may omit it, but can't change it).
    const nonce = claims["nonce"];
    if (expect.nonceOptional) {
      if (nonce !== undefined && expect.nonce !== undefined && nonce !== expect.nonce) throw new OidcSignInError("bad_nonce", "the refreshed ID token's nonce changed");
    } else if (expect.nonce === undefined || typeof nonce !== "string" || nonce !== expect.nonce) {
      throw new OidcSignInError("bad_nonce", "the ID token's nonce is not this sign-in's");
    }

    // auth_time: present and fresh when the broker asked for a fresh sign-in.
    const authTime = claims["auth_time"];
    if (authTime !== undefined && (typeof authTime !== "number" || authTime > nowSec + s.clockSkewSeconds)) throw new OidcSignInError("bad_token", "auth_time is not a past time");
    if (expect.requireAuthTime && typeof authTime !== "number") throw new OidcSignInError("not_fresh", "the ID token has no auth_time (for Entra, add the optional auth_time claim)");
    if (expect.freshSince !== undefined && typeof authTime === "number" && authTime < expect.freshSince - s.clockSkewSeconds) throw new OidcSignInError("not_fresh", "the provider didn't sign the person in again");
    return claims;
  }

  /** The binding (spec 5.2): iss + sub; Entra: the tenant's issuer + oid. Never email, preferred_username or upn. */
  bindingOf(claims: JWTPayload): { iss: string; sub: string } {
    const iss = String(claims.iss);
    if (this.settings.provider === "entra") {
      const oid = claims["oid"];
      if (typeof oid !== "string" || !GUID.test(oid)) throw new OidcSignInError("missing_claim", "the ID token has no oid (object id)");
      return { iss, sub: oid };
    }
    const sub = claims.sub;
    if (typeof sub !== "string" || sub.length === 0 || sub.length > 255) throw new OidcSignInError("missing_claim", "the ID token's sub is missing or too long");
    return { iss, sub };
  }

  /** The address alias, from the configured claim, on a domain this provider (or this tenant) may sign in for. */
  addressOf(claims: JWTPayload): Address {
    const s = this.settings;
    const raw = claims[s.addressClaim];
    if (typeof raw !== "string" || raw.length === 0 || raw.length > 254) throw new OidcSignInError("no_address", `the ID token has no ${s.addressClaim}`);
    if (s.requireVerifiedEmail) {
      const v = claims["email_verified"];
      if (v !== true && v !== "true") throw new OidcSignInError("email_not_verified", `the ID token's ${s.addressClaim} is not verified`);
    }
    let address: Address;
    try {
      address = parseAddress(raw);
    } catch {
      throw new OidcSignInError("no_address", `the ID token's ${s.addressClaim} is not an address`);
    }
    const allowed = s.provider === "entra" ? s.tenants?.[String(claims["tid"])] ?? [] : s.domains;
    if (!allowed.includes(domainOf(address))) throw new OidcSignInError("address_not_allowed", `the address's domain ${domainOf(address)} isn't served for this ${s.provider === "entra" ? "tenant" : "provider"}`);
    return address;
  }

  /** Group claims for the policy's claim-based groups, keyed by the binding's issuer. An overflowed claim refuses. */
  groupsOf(claims: JWTPayload, issuer: string): { issuer: string; name: string; value: string }[] {
    const out: { issuer: string; name: string; value: string }[] = [];
    const names = claims["_claim_names"];
    for (const name of this.settings.groupClaims) {
      // Distributed claims (OpenID Connect Core 5.6.2): Entra's groups overage sends a link to Microsoft Graph instead
      // of the list. `hasgroups` is the same signal in Entra's implicit flow.
      if ((isObject(names) && name in names) || (name === "groups" && claims["hasgroups"] !== undefined)) {
        throw new OidcSignInError("groups_overage", `the ID token's ${name} claim overflowed (a link instead of the list)`);
      }
      const v = claims[name];
      const values = typeof v === "string" ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= 256) : [];
      if (values.length > MAX_GROUP_VALUES) throw new OidcSignInError("groups_overage", `the ID token lists more than ${MAX_GROUP_VALUES} ${name}`);
      for (const value of new Set(values)) out.push({ issuer, name, value });
    }
    return out;
  }

  /** The verified identity a sign-in gives: binding, address, display name and group claims. */
  identityFrom(claims: JWTPayload): OidcIdentity {
    const binding = this.bindingOf(claims);
    // Entra: a guest's token names its home identity provider in `idp` (another tenant, a personal Microsoft account
    // or a one-time passcode), and its preferred_username is that home account's name, which the host organization
    // doesn't control. Members only, unless the configuration allows guests.
    const idp = claims["idp"];
    if (this.settings.provider === "entra" && !this.settings.allowGuests && idp !== undefined && idp !== claims.iss) {
      throw new OidcSignInError("guest_account", "the ID token's idp is not its issuer (a guest account)");
    }
    const address = this.addressOf(claims);
    const groups = this.groupsOf(claims, binding.iss);
    const name = typeof claims["name"] === "string" ? claims["name"].trim().slice(0, 120) : "";
    const authTime = claims["auth_time"];
    const amr = Array.isArray(claims["amr"]) ? claims["amr"].filter((x): x is string => typeof x === "string" && /^[a-z0-9_-]{1,16}$/i.test(x)).slice(0, 8) : [];
    const tid = this.settings.provider === "entra" ? String(claims["tid"]) : undefined;
    return {
      address,
      ...(name ? { display_name: name } : {}),
      method: "oidc",
      iss: binding.iss,
      sub: binding.sub,
      claims: groups,
      verified_at: this.clock.now().toISOString(),
      ...(typeof authTime === "number" ? { auth_time: authTime } : {}),
      ...(amr.length ? { amr } : {}),
      ...(tid ? { tenant: tid } : {}),
    };
  }

  /** IdentityVerifier: an ID token the broker obtained itself, with the nonce it sent. */
  async verify(assertion: IdentityAssertion): Promise<VerifiedIdentity> {
    if (assertion.kind !== "oidc" || assertion.nonce === undefined) throw new AlpError("identity_mismatch", "an OIDC sign-in needs an ID token and its nonce", { status: 401 });
    try {
      return this.identityFrom(await this.validateIdToken(assertion.id_token, { nonce: assertion.nonce, checkAge: true }));
    } catch (err) {
      if (isOidcSignInError(err)) throw new AlpError("identity_mismatch", `sign-in refused (${err.reason})`, { status: 401 });
      throw err;
    }
  }
}

function joseFailure(err: unknown): OidcSignInError {
  if (err instanceof OidcSignInError) return err;
  if (err instanceof joseErrors.JWTExpired) return new OidcSignInError("expired", "the ID token has expired");
  if (err instanceof joseErrors.JWSSignatureVerificationFailed || err instanceof joseErrors.JWKSNoMatchingKey || err instanceof joseErrors.JOSEAlgNotAllowed || err instanceof joseErrors.JWKSMultipleMatchingKeys) {
    return new OidcSignInError("bad_signature", `the ID token's signature doesn't verify (${(err as { code?: string }).code ?? "error"})`);
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) return new OidcSignInError(err.claim === "nbf" ? "bad_token" : "missing_claim", `ID token claim ${err.claim}: ${err.reason}`);
  if (err instanceof joseErrors.JOSEError) return new OidcSignInError("bad_token", `the ID token is malformed (${err.code})`);
  return new OidcSignInError("bad_token", errMessage(err));
}
