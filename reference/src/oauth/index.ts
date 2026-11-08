// SPDX-License-Identifier: FSL-1.1-ALv2
// src/oauth: the client binding's OAuth 2.1 authorization server and protected-resource side (spec 5.6, 5.7).
// oidc-provider 9.13.3 inside the broker: client ID metadata documents first, dynamic registration
// (application_type required) and pre-registered clients; PKCE S256 only; RFC 9207 iss; RFC 8707 audience-bound JWT
// access tokens (10 minutes); rotating refresh tokens with reuse detection; RFC 9728 and RFC 8414 metadata; the
// connector sign-in page (dev test identities with a per-session secret, or the organization's OpenID provider:
// oidc.ts, oidc-signin.ts); personal access tokens minted on the web view.

export { StateAdapter, grantIdsFor } from "./adapter.ts";
export { BindingState, sha256b64u } from "./state.ts";
export type { BindingStateData, PatRecord, PendingConnection } from "./state.ts";
export { DEFAULT_REDIRECT_HOSTS, clientAttestation, isCimdClientId, redirectUriPermitted, suggestedLabel } from "./clients.ts";
export type { RedirectPolicy } from "./clients.ts";
export { generateAuthServerKeys, loadAuthServerKeys, publicJwks } from "./keys.ts";
export type { AuthServerKeys } from "./keys.ts";
export { OAUTH_SCOPES, ROUTES, cimdUrlAllowed, createAuthServer } from "./provider.ts";
export type { AuthServer, AuthServerOptions, OAuthScope } from "./provider.ts";
export { CONNECTOR_CALLBACK_PATH, SignInLimiter, bindDelegate, interactionRouter } from "./interaction.ts";
export { ENTRA_AUTHORITY, ID_TOKEN_ALGORITHMS, OidcRelyingParty, OidcSignInError, isOidcSignInError, parseOidcConfig } from "./oidc.ts";
export type { IdTokenExpectations, OidcIdentity, OidcRefusal, OidcSettings } from "./oidc.ts";
export { OidcSignIn, SecretBox } from "./oidc-signin.ts";
export type { InteractionOptions } from "./interaction.ts";
export { metadataRouter } from "./metadata.ts";
export { ResourceGuard, bearerChallenge, metadataUrlFor, protectedResourceMetadata } from "./resource.ts";
export type { AuthContext, AuthOutcome, ResourceKind } from "./resource.ts";
export { PAT_CLIENT_ID, findPat, mintPat, patsOf, revokePat, revokePatsOfDelegate } from "./pat.ts";
