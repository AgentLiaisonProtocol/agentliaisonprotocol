// SPDX-License-Identifier: FSL-1.1-ALv2
// src/federation: broker-to-broker transport and discovery (spec 4 and 12.2).
//  - HardenedFetcher (fetcher.ts, net-guard.ts): the only way to fetch a URL named by inbound data.
//  - HttpsDomainResolver (resolver.ts): domain documents and JWKS over HTTPS, with the cache, rollback and
//    restriction rules; StaticTxtLookup / systemTxtLookup for the TXT hint.
//  - createInboxHandler (inbox.ts) and FederationServer (server.ts): the inbox and JWKS endpoints.
//  - HttpsFederationTransport (transport.ts): delivery with retries, idempotency by id and TTL expiry.
//  - Domain documents (domain-authority.ts) and DomainAuthorityServer (server.ts).
//  - Optional RFC 9421 request signatures and RFC 9530 digests (http-signatures.ts).
//  - InProcessFederation and StaticResolver: the in-process versions (tests and the core demo).
//  - startHttpWorld (http-world.ts): the three-broker world over localhost HTTP (tests, demo:federation).

export { InProcessFederation } from "./in-process.ts";
export type { InboundHandler, WireLogEntry } from "./in-process.ts";
export { StaticResolver } from "./static-resolver.ts";
export { HardenedFetcher, FetchFailure, isJsonContentType, USER_AGENT } from "./fetcher.ts";
export type { FetchFailureKind, FetcherOptions, HttpResponse, HostResolver } from "./fetcher.ts";
export { checkDevHostMap, fetchTarget, isPublicAddress, isReservedExampleName } from "./net-guard.ts";
export type { DevHostMap, FetchTarget } from "./net-guard.ts";
export { DiscoveryError, HttpsDomainResolver, StaticTxtLookup, systemTxtLookup } from "./resolver.ts";
export type { ResolverDiagnostic, ResolverOptions, TxtLookup } from "./resolver.ts";
export { FEDERATION_PATHS, MAX_PINS, brokerEntry, buildDomainDocument, checkEndpointOrigins } from "./domain-authority.ts";
export type { BrokerListing, DomainDocumentInput } from "./domain-authority.ts";
export { HTTP_STATUS, createInboxHandler, pinnedKey } from "./inbox.ts";
export type { InboxBroker, InboxLogEntry, InboxOptions, RequestSignatureMode } from "./inbox.ts";
export { DomainAuthorityServer, FederationServer, assertPortsFree, closeServer, listenOn } from "./server.ts";
export type { FederationServerOptions, TlsOptions, WireRecord } from "./server.ts";
export { DEFAULT_RETRY_POLICY, HttpsFederationTransport, SPEC_RETRY_SCHEDULE, parseRetryAfter } from "./transport.ts";
export type { DeliveryAttempt, HttpsTransportOptions, RetryPolicy } from "./transport.ts";
export {
  FEDERATION_SIGNATURE_PROFILE,
  checkContentDigest,
  contentDigest,
  parseDictionary,
  signRequest,
  signatureBase,
  verifyRequestSignature,
} from "./http-signatures.ts";
export type { RequestSignatureCheck, SignableRequest, SigningKey } from "./http-signatures.ts";
export { StrictJsonError, parseStrictJson, parseStrictJsonBytes } from "./strict-json.ts";
