// The checks of alp-check, as plain data. No side effects.
//
// Each check cites the section of spec/alp-v0.1.md it enforces and quotes the sentence word for word. Where a
// check needs two separate parts of one section, `quote` joins them with " … " and each part appears word for word,
// in that order, in the section (test/quotes.test.mjs verifies this).
//
// `level` is "required" or "recommended": a failed required check is a failure and sets exit code 1; a failed
// recommended check is a warning. `basis` says why the level is what it is:
// - { kind: "keyword", keyword }: the quote holds that BCP 14 key word (MUST, SHOULD, RECOMMENDED, ...);
// - { kind: "stated" }: the quote states the behaviour as fact, with no key word, in a normative section (Core, or
//   Experimental, which `maturity` then says);
// - a stated basis may name the `clause` of the quote that states the behaviour, when another clause of the same
//   sentence holds a key word for something else;
// - in either of those, `of` names the party the sentence binds when it is not the target (the fetching broker or
//   peer of Sections 4.2.1 and 4.3, or the domain);
// - { kind: "reference", text, sentences }: the rule is in a document the quoted ALP sentence adopts; `sentences`
//   holds that document's sentence, word for word as read on 2026-11-20.
// A check on what a domain or broker serves whose sentence binds the party that fetches (Section 4.3) is
// recommended: its warning explains why a peer would fail. The exception is the validity rules of Section 4.2.1,
// which bind the fetching broker too: a document peers must treat as absent leaves the domain without the document
// Section 4.2 has it publish, so those checks are required.
//
// Licensed under Apache-2.0.

export const VERSION = "0.1";
export const USER_AGENT = "alp-check/0.1 (+https://github.com/AgentLiaisonProtocol/agentliaisonprotocol)";

export const FAMILIES = [
  { id: "document", title: "Domain document" },
  { id: "keys", title: "Keys" },
  { id: "dns", title: "DNS hint" },
  { id: "signin", title: "Sign-in metadata" },
  { id: "binding", title: "Client binding without a token" },
  { id: "inbox", title: "Inbox refusals before authentication" },
];

// Section 18.3: the HTTP status of each error code (`unreachable` has none).
export const REGISTRY = {
  invalid_input: 400,
  identity_mismatch: 403,
  unknown_scope: 422,
  unknown_type: 422,
  schema_invalid: 422,
  body_too_large: 413,
  no_relationship: 403,
  type_not_allowed: 403,
  not_disclosed: 403,
  org_policy: 403,
  federation_blocked: 403,
  client_not_allowed: 403,
  blocked: 403,
  dlp_blocked: 403,
  rate_limited: 429,
  thread_state: 409,
  needs_ratification: 409,
  unknown_recipient: 404,
  discovery_failed: 503,
  unreachable: null,
  expired: 400,
  bad_envelope: 400,
  unsupported_version: 400,
  bad_signature: 401,
  wrong_audience: 400,
  replay: 409,
  broker_not_authorized: 403,
  not_accepted: 403,
  constraints_unsupported: 422,
  internal: 500,
};

const INVALID = "A document is invalid, and a broker MUST treat the domain as having no valid document (`discovery_failed`), when any of these hold:";
const PRM = "The protected resource serves OAuth 2.0 Protected Resource Metadata [RFC 9728] at the well-known locations the MCP specification names, and answers unauthenticated requests with `401` and a `WWW-Authenticate: Bearer` header carrying `resource_metadata` and `scope`.";
const AS_META = "The authorization server publishes RFC 8414 metadata and SHOULD also publish OpenID Connect discovery.";
const JWKS = "A broker publishes its public keys as a JWK Set [RFC 7517] at `jwks_uri`, on its own origin (`schemas/jwks.schema.json`).";
const JSON_TYPE = "Accept only status 200 with a JSON content type.";
const SIZE = "At most 64 KiB per document and 5 seconds per fetch.";
const FALLBACK = "To find a domain's document, a broker fetches location 1. If that fails with HTTP 404 or 410, or the name has no address records, it fetches location 2.";
const FEDERATING = ["OB-6", "HB-5"];

// Rules from documents Section 5.6 adopts, as read on 2026-11-20.
const RFC9728 = {
  kind: "reference",
  text: "RFC 9728 Section 3.3",
  sentences: [
    "The `resource` value returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path suffix was inserted to create the URL used to retrieve the metadata.",
    "If the protected resource metadata was retrieved from a URL returned by the protected resource via the `WWW-Authenticate` `resource_metadata` parameter, then the `resource` value returned MUST be identical to the URL that the client used to make the request to the resource server.",
  ],
};
const MCP_AS = {
  kind: "reference",
  text: "the MCP authorization specification (revision 2026-07-28), \"Authorization Server Location\"",
  sentences: ["The Protected Resource Metadata document returned by the MCP server MUST include the `authorization_servers` field containing at least one authorization server."],
};
const MCP_ISSUER_TEXT = "the MCP authorization specification (revision 2026-07-28), \"Authorization Server Metadata Discovery\"";
const MCP_ISSUER_SENTENCE = "the `issuer` value in the document MUST be identical to the issuer identifier used to construct the well-known URL";
const MCP_ISSUER = { kind: "reference", text: MCP_ISSUER_TEXT, sentences: [MCP_ISSUER_SENTENCE] };
const INBOX = ["OB-6", "HB-5", "PB-2"];

export const CHECKS = [
  // ------------------------------------------------------------------ domain document (Sections 4.2, 4.2.1, 4.3, 4.8)
  {
    id: "document.found",
    family: "document",
    level: "required",
    basis: { kind: "stated" },
    section: "4.2",
    title: "A peer that follows Section 4.3 finds the domain document: status 200 at https://<domain>/.well-known/alp.json, or at https://alp.<domain>/.well-known/alp.json after 404, 410 or no address records at the first location",
    quote: "A domain authority that wants its addresses to federate publishes a domain document.",
    requirements: FEDERATING,
    note: "Section 4.3 stops a peer at the first location on any answer but 404, 410 or no address records there. A redirect, another status, or a certificate that does not validate at the first location is a failure even when the second location serves the document; a 429, a 5xx, a timeout or a refused connection there may be temporary, so alp-check does not decide. A certificate that does not validate at the second location, which a peer uses after 404, 410 or no address records at the first, is a failure too.",
  },
  {
    id: "document.fallback",
    family: "document",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "A peer that follows Section 4.3 reaches the document: location 1 serves it, or answers 404 or 410 (or its name has no address records) so that the peer goes on to location 2",
    quote: FALLBACK,
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer, and the same paragraph goes on: \"Any other failure, including a TLS failure, is a temporary failure: the broker MUST NOT fall back to location 2\". A location 1 that redirects, refuses, or serves another page with status 200 stops every peer there, even when location 2 serves the document.",
  },
  {
    id: "document.tls",
    family: "document",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "The document is served over HTTPS with a certificate valid for the host, because peers accept nothing else",
    quote: "HTTPS only, on port 443, with a certificate valid for the host.",
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer. The checker relies on the certificate checks of the Node.js HTTPS client. A certificate that does not validate, at whichever location a peer uses, gives a warning (this check is recommended); any other TLS failure may be the checker's own network and is undecided. With --dev-map this check is skipped, never passed.",
  },
  {
    id: "document.content-type",
    family: "document",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "The document is served with a JSON content type (application/json or application/<name>+json), because peers accept nothing else",
    quote: JSON_TYPE,
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer. The specification does not list the JSON content types; the checker accepts application/json and any application/<name>+json, with any parameters.",
  },
  {
    id: "document.size",
    family: "document",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "The document is at most 64 KiB, because peers read no more",
    quote: SIZE,
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer. The checker does not judge the 5-second limit: its own network is not a peer's.",
  },
  {
    id: "document.schema",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "The document is JSON and valid against schemas/domain-document.schema.json (members, `alp` \"0.1\", ranges such as `max_age` 60 to 86400, 1 to 16 entries, 1 to 4 security contacts)",
    quote: `${INVALID} … it fails the schema`,
    requirements: [...FEDERATING, "PB-7"],
  },
  {
    id: "document.domain-matches",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST" },
    section: "4.2",
    title: "The document's `domain` is the domain that was asked for",
    quote: "MUST equal the domain the document was fetched for.",
    requirements: FEDERATING,
  },
  {
    id: "document.unique-ids",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "No two broker entries have the same `id`",
    quote: `${INVALID} … two entries have the same \`id\`;`,
    requirements: FEDERATING,
  },
  {
    id: "document.one-wildcard",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "At most one broker entry has \"principals\": \"*\"",
    quote: `${INVALID} … more than one entry has \`"principals": "*"\`;`,
    requirements: FEDERATING,
  },
  {
    id: "document.no-overlap",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "No address appears in more than one explicit `principals` list",
    quote: `${INVALID} … an address appears in more than one explicit list (overlapping authorizations);`,
    requirements: FEDERATING,
  },
  {
    id: "document.addresses-on-domain",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "Every explicitly listed address is on the document's `domain`",
    quote: `${INVALID} … an explicitly listed address is not on \`domain\`;`,
    requirements: FEDERATING,
  },
  {
    id: "document.urls-on-origin",
    family: "document",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST", of: "the fetching broker" },
    section: "4.2.1",
    title: "Each entry's `inbox`, `jwks_uri`, `mcp`, `rest` and `operator_statement` are on the entry's own origin (`id`)",
    quote: `${INVALID} … \`inbox\`, \`jwks_uri\`, \`mcp\`, \`rest\` or \`operator_statement\` is not on the entry's own origin (\`id\`).`,
    requirements: FEDERATING,
  },
  {
    id: "document.revoked-not-pinned",
    family: "document",
    level: "recommended",
    basis: { kind: "stated", of: "the domain" },
    section: "4.8",
    title: "No thumbprint listed in `revoked_jkt` is still pinned in an entry's `jkt` (peers refuse the key anyway)",
    quote: "The domain removes the thumbprint from `jkt` and adds `{ \"jkt\", \"compromised_since\" }` to `revoked_jkt`.",
    requirements: FEDERATING,
    note: "Section 4.8 rule 5 states the domain's compromise procedure with no key word, and Section 4.2.1 does not make such a document invalid; verifiers refuse anything signed with a revoked key whether or not it is still pinned.",
  },

  // ------------------------------------------------------------------ keys (Section 4.8)
  {
    id: "keys.served",
    family: "keys",
    level: "required",
    basis: { kind: "stated" },
    section: "4.8",
    title: "The broker's JWKS is served with status 200 at the entry's `jwks_uri`",
    quote: JWKS,
    requirements: FEDERATING,
  },
  {
    id: "keys.content-type",
    family: "keys",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "The JWKS is served with a JSON content type (application/json or application/<name>+json, such as application/jwk-set+json), because peers accept nothing else",
    quote: JSON_TYPE,
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer, whose fetcher rules apply to a JWKS (Section 4.3, first paragraph).",
  },
  {
    id: "keys.size",
    family: "keys",
    level: "recommended",
    basis: { kind: "stated", of: "the fetching peer" },
    section: "4.3",
    title: "The JWKS is at most 64 KiB, because peers read no more",
    quote: SIZE,
    requirements: FEDERATING,
    note: "This sentence binds the fetching peer, whose fetcher rules apply to a JWKS (Section 4.3, first paragraph).",
  },
  {
    id: "keys.schema",
    family: "keys",
    level: "required",
    basis: { kind: "stated" },
    section: "4.8",
    title: "The JWKS is valid against schemas/jwks.schema.json: 1 to 32 keys, each OKP/Ed25519 with `alg` Ed25519 or EC/P-256 with `alg` ES256, `use` \"sig\" and one `alp_use`, and no private members",
    quote: JWKS,
    requirements: FEDERATING,
  },
  {
    id: "keys.current-key-pinned",
    family: "keys",
    level: "required",
    basis: { kind: "stated" },
    section: "4.2.1",
    title: "At least one thumbprint the entry pins in `jkt` is that of a `federation` key in the broker's JWKS (the current key); other pinned thumbprints, such as a next key not yet published, are reported as notes",
    quote: "1 to 4 RFC 7638 thumbprints of the broker's federation signing keys: the current key and the next one.",
    requirements: FEDERATING,
  },
  {
    id: "keys.no-unpinned-federation",
    family: "keys",
    level: "recommended",
    basis: { kind: "keyword", keyword: "MUST NOT", reading: "one of two readings" },
    section: "4.8",
    title: "Every `federation` key in the broker's JWKS is pinned in this domain's entry for that broker (Section 4.8 rule 1 read as: every domain that lists the broker pins every federation key it publishes; under the other reading, a key that only another listing domain pins is allowed)",
    quote: "A broker MUST NOT publish federation keys that the domains listing it haven't pinned.",
    requirements: FEDERATING,
    note: "Two readings of \"the domains listing it\": each listing domain pins every federation key the broker publishes, or every published key is pinned by at least one of them (a Hosted Broker could then keep one key per customer domain). alp-check sees one domain, so it can check only the first reading, and reports a difference as a warning. Section 4.8 rule 4 also leaves a window: after rotation the domains unpin the old key, and a broker that follows the rule as written may still publish it for a while.",
  },
  {
    id: "keys.kid-thumbprint",
    family: "keys",
    level: "recommended",
    basis: { kind: "keyword", keyword: "RECOMMENDED" },
    section: "4.8",
    title: "Each key's `kid` is its RFC 7638 thumbprint",
    quote: "`kid`: RECOMMENDED to be the key's RFC 7638 thumbprint;",
    requirements: [],
  },

  // ------------------------------------------------------------------ DNS hint (Section 4.7)
  {
    id: "dns.txt-grammar",
    family: "dns",
    level: "recommended",
    basis: { kind: "stated" },
    section: "4.7",
    title: "When _alp.<domain> has TXT records, there is exactly one and it is v=ALP1; id=<1 to 32 letters and digits> with nothing else, because peers ignore any other",
    quote: "The record carries only the version tag `v=ALP1` and an `id` of 1 to 32 letters and digits … A record with any other member, or more than one record, is ignored.",
    requirements: [],
    note: "The record is optional; with none, this check is skipped. The specification shows one space after the semicolon and does not say whether other spacing is allowed; the checker accepts any number of spaces there.",
  },
  {
    id: "dns.txt-id-serial",
    family: "dns",
    level: "recommended",
    basis: { kind: "keyword", keyword: "SHOULD" },
    section: "4.7",
    title: "The TXT record's `id` equals the document's current `serial`",
    quote: "The record carries only the version tag `v=ALP1` and an `id` of 1 to 32 letters and digits, which SHOULD equal the document's current `serial`.",
    requirements: [],
  },

  // ------------------------------------------------------------------ sign-in metadata (Section 5.6)
  {
    id: "signin.prm",
    family: "signin",
    level: "required",
    basis: RFC9728,
    section: "5.6",
    title: "Protected resource metadata is served for the endpoint, and its `resource` is the identifier RFC 9728 ties to where it was found (for the REST mirror, the REST base URL is accepted too)",
    quote: PRM,
    requirements: ["BC-5"],
    note: "The checker looks where an MCP client looks: the URL in the 401 challenge's `resource_metadata` (when it is on the endpoint's origin), then the RFC 9728 location with the endpoint's path, then the one without. Found at the location with the path, `resource` must be the endpoint's URL; at the location without a path, the origin; through the challenge, the URL the request went to. For the REST mirror the request goes to a tool path, while Section 5.6 item 6 binds tokens to the REST base URL, so either passes.",
  },
  {
    id: "signin.prm-authorization-server",
    family: "signin",
    level: "required",
    basis: MCP_AS,
    section: "5.6",
    title: "The MCP endpoint's protected resource metadata names at least one authorization server in `authorization_servers` (for the REST mirror's metadata this is reported as a note)",
    quote: "The broker runs an authorization server, or a facade in front of one, that follows the MCP authorization specification for each MCP revision the broker serves [MCP-2026-07-28], with these ALP requirements.",
    requirements: ["BC-5"],
    note: "RFC 9728 makes `authorization_servers` optional; the MCP authorization specification, which this sentence adopts, requires it of an MCP server. ALP's text does not say the same of the REST mirror, so there it is a note.",
  },
  {
    id: "signin.prm-scopes",
    family: "signin",
    level: "required",
    basis: { kind: "stated" },
    section: "5.6",
    title: "The protected resource metadata's `scopes_supported` includes \"read\" and \"send\", in either order; any other value is reported as a note",
    quote: "The protected resource metadata lists `scopes_supported: [\"read\", \"send\"]`.",
    requirements: ["BC-5"],
    note: "The MCP authorization specification says a server SHOULD NOT list `offline_access` in `scopes_supported`, while Section 5.6 item 7 issues refresh tokens for that scope; the checker reports extra values without judging them.",
  },
  {
    id: "signin.as-metadata",
    family: "signin",
    level: "required",
    basis: MCP_ISSUER,
    // When no RFC 8414 metadata is served, the failure rests on Section 5.6's own sentence, not on the issuer rule.
    // The quote's SHOULD is for OpenID Connect discovery; `clause` is the part that states this check's behaviour.
    otherBases: { "not-served": { kind: "stated", clause: "The authorization server publishes RFC 8414 metadata" } },
    section: "5.6",
    title: "The authorization server serves RFC 8414 metadata at its well-known location, with `issuer` equal to its identifier",
    quote: AS_META,
    requirements: ["BC-5"],
    note: "That the metadata is served is stated in Section 5.6; that `issuer` equals the identifier is the MCP authorization specification's rule. The location is RFC 8414's (Section 3.1: for an issuer with a path, the well-known string goes between the host and the path); RFC 8414 Section 3.3 states the same `issuer` rule.",
  },
  {
    id: "signin.oidc-discovery",
    family: "signin",
    level: "recommended",
    basis: { kind: "keyword", keyword: "SHOULD" },
    section: "5.6",
    title: "The authorization server also serves OpenID Connect discovery, with the same `issuer`",
    note: `The level follows the SHOULD for publishing it. The \`issuer\` comparison follows ${MCP_ISSUER_TEXT}, which covers both metadata documents: "${MCP_ISSUER_SENTENCE}".`,
    quote: AS_META,
    requirements: ["BC-5"],
  },
  {
    id: "signin.pkce-s256",
    family: "signin",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST" },
    section: "5.6",
    title: "The authorization server metadata lists `code_challenge_methods_supported` as exactly [\"S256\"]",
    quote: "The metadata MUST list `code_challenge_methods_supported: [\"S256\"]`.",
    requirements: ["BC-5"],
  },
  {
    id: "signin.iss-parameter",
    family: "signin",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST" },
    section: "5.6",
    title: "The authorization server metadata advertises `authorization_response_iss_parameter_supported: true` (the checker does not see authorization responses)",
    quote: "The authorization server MUST include `iss` in every authorization response, including errors [RFC 9207], and MUST advertise `authorization_response_iss_parameter_supported: true`.",
    requirements: ["BC-5"],
  },
  {
    id: "signin.cimd",
    family: "signin",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST" },
    section: "5.6",
    title: "The authorization server metadata advertises `client_id_metadata_document_supported: true`",
    quote: "It MUST support OAuth Client ID Metadata Documents [CIMD] and advertise `client_id_metadata_document_supported: true`.",
    requirements: ["BC-5"],
  },
  {
    id: "signin.revocation",
    family: "signin",
    level: "recommended",
    basis: { kind: "keyword", keyword: "SHOULD" },
    section: "5.6",
    title: "The authorization server metadata advertises a `revocation_endpoint` (RFC 7009)",
    quote: "The authorization server SHOULD offer token revocation [RFC 7009].",
    requirements: ["BC-5"],
    note: "A server could offer revocation without advertising it; the checker sees only the metadata.",
  },

  // ------------------------------------------------------------------ client binding without a token (Sections 5.6, 12.1)
  {
    id: "binding.mcp-challenge",
    family: "binding",
    level: "required",
    basis: { kind: "stated" },
    section: "5.6",
    title: "An MCP request with no token is answered 401 with a WWW-Authenticate: Bearer challenge carrying `resource_metadata` and `scope`",
    quote: PRM,
    requirements: ["BC-5"],
  },
  {
    id: "binding.rest-challenge",
    family: "binding",
    level: "required",
    basis: { kind: "stated" },
    section: "5.6",
    title: "A REST mirror request with no token (POST {rest}/alp_whoami) is answered 401 with a WWW-Authenticate: Bearer challenge carrying `resource_metadata` and `scope`",
    quote: PRM,
    requirements: ["BC-5"],
  },

  // ------------------------------------------------------------------ inbox refusals before authentication (Sections 8, 12.2, 16)
  {
    id: "inbox.version",
    family: "inbox",
    level: "required",
    basis: { kind: "stated" },
    section: "16",
    title: "An envelope whose `alp` is \"0.0\" is refused with `unsupported_version`",
    quote: "A broker that receives an object with a `alp` value it doesn't implement refuses it (`unsupported_version`).",
    requirements: INBOX,
    note: "The probe necessarily fails the schema too, which fixes `alp` to \"0.1\". The code is still `unsupported_version`: Section 16 names it for an unknown `alp` value, and acceptance step 0 checks `alp` before the schema (Section 12.2.4).",
  },
  {
    id: "inbox.strict-json",
    family: "inbox",
    level: "required",
    basis: { kind: "keyword", keyword: "MUST" },
    section: "8.3",
    title: "An envelope with a duplicate member name is refused with `bad_envelope` (acceptance step 0)",
    quote: "A broker MUST parse each received object once, with a parser that refuses duplicate member names, lone surrogates and numbers outside IEEE 754 double precision, and MUST then evaluate, sign, store and deliver that same parsed object.",
    requirements: ["BC-15", ...INBOX],
    note: "The code comes from acceptance step 0 (Section 12.2.4) and the registry (Section 18.3: \"Fails structure, parsing or lifetime rules\").",
  },
  {
    id: "inbox.schema",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.4",
    title: "An envelope that fails its schema (it has no `broker_sig`) is refused with `bad_envelope`",
    quote: "the shape (message or control type) selects the schema and the object passes it",
    requirements: INBOX,
  },
  {
    id: "inbox.lifetime",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.4",
    title: "An envelope whose `expires_at` is more than 7 days after its `created_at`, and one whose `expires_at` is before its `created_at`, are each refused with `bad_envelope`",
    quote: "`expires_at` is after `created_at` and at most 7 days later",
    requirements: INBOX,
  },
  {
    id: "inbox.created-ahead",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.4",
    title: "An envelope whose `created_at` is one hour ahead of the checker's clock is refused with `bad_envelope`",
    quote: "`created_at` is at most 300 seconds ahead of the broker's clock.",
    requirements: INBOX,
    note: "The probe is one hour ahead, so a broker whose clock differs from the checker's by less than 55 minutes is judged correctly.",
  },
  {
    id: "inbox.delegate-owner",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.4",
    title: "An envelope whose `from.delegate` is an agent of another address than `from.address`, and one whose `to.delegate` is an agent of another address than `to.address`, are each refused with `bad_envelope`",
    quote: "`from.delegate` and `to.delegate`, when present, are delegate ids of `from.address` and `to.address`",
    requirements: INBOX,
    note: "The `from.delegate` probe is a `connection_request`; the `to.delegate` probe is a `request` message, because a control envelope's `to` has no `delegate`.",
  },
  {
    id: "inbox.unknown-sender-domain",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.4",
    title: "A well-formed envelope from a sender whose domain cannot exist (.invalid) is refused at step 1 with `discovery_failed` or `broker_not_authorized`; the specification can be read either way, so both pass",
    quote: "The sender's address domain has a valid, current document (Section 4.4); it lists `origin_broker`; a key it pins for that broker, not revoked, verifies `broker_sig` (Section 8.7).",
    requirements: INBOX,
    note: "Section 4.4 gives `discovery_failed` while a broker has no valid document for a domain; Section 8.7 gives `broker_not_authorized` for an origin broker the document doesn't list at all, and the acceptance vectors expect it for a domain with no document.",
  },
  {
    id: "inbox.error-shape",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.3",
    title: "Every refusal of the probes above is an unsigned error: the registry's HTTP status for its code, a body { \"error\": { \"code\", \"message\" } }, and no receipt",
    quote: "If the envelope can't be authenticated (steps 0 and 1 below), the inbox answers with an unsigned error: the HTTP status for the code and `{ \"error\": { \"code\", \"message\" } }`.",
    requirements: INBOX,
    note: "Members beyond `code` and `message` are reported as notes, not failures: the sentence shows the shape, not a closed list. A 401 answer is not judged: Section 12.2.2 lets a broker require signed requests and gives no form for refusing an unsigned one. When every probe is answered 401 the check is skipped; otherwise a 401's shape is a note.",
  },
  {
    id: "inbox.retry-after",
    family: "inbox",
    level: "required",
    basis: { kind: "stated", maturity: "Experimental" },
    section: "12.2.3",
    title: "Every 429 or 503 answer from the inbox carries Retry-After",
    quote: "`429` and `503` carry `Retry-After`.",
    requirements: INBOX,
    note: "Unlike the other inbox checks, this one counts every 429 or 503 the inbox URL answers, a front server's error page included: the sentence binds what is answered at the inbox, whoever serves it.",
  },
];

export const BY_ID = new Map(CHECKS.map((c) => [c.id, c]));

/** Requirements that apply to a broker when it federates; a --broker run (a Local-profile broker) does not list them. */
export const FEDERATION_REQUIREMENTS = new Set(["OB-6", "HB-5", "PB-1", "PB-2", "PB-7"]);

/**
 * The basis a result rests on: the check's own, or one of its `otherBases` when the result names it (`basisKey`), for
 * example "not-served" for signin.as-metadata when no RFC 8414 metadata is served.
 */
export function basisOf(c, key = null) {
  return (key && c.otherBases && Object.hasOwn(c.otherBases, key) && c.otherBases[key]) || c.basis;
}

/** The basis in a few words, for the README's table: the key word, "stated", or the document adopted. */
export function basisShort(c) {
  const main = shortOf(c.basis);
  const others = Object.entries(c.otherBases ?? {}).map(([key, b]) => `${shortOf(b)} when ${key.replace(/-/g, " ")}`);
  return [main, ...others].join("; ");
}

function shortOf(b) {
  if (b.kind === "keyword") return `${b.keyword}${b.reading ? ", under one reading" : ""}${b.of ? `, for ${b.of}` : ""}`;
  if (b.kind === "stated") return b.of ? `stated, for ${b.of}` : "stated";
  return b.text;
}

/** The level and its basis as the report prints them, for example "required (MUST, Section 4.2)". */
export function basisLabel(c, key = null) {
  const b = basisOf(c, key);
  if (b.kind === "keyword") return `${c.level} (${b.keyword}, Section ${c.section}${b.reading ? `, under ${b.reading}` : ""}${b.of ? `, as a rule for ${b.of}` : ""})`;
  if (b.kind === "stated") return `${c.level} (stated in Section ${c.section}${b.maturity ? `, ${b.maturity}` : ""}${b.of ? `, as a rule for ${b.of}` : ""})`;
  return `${c.level} (${b.text}, adopted by Section ${c.section})`;
}

// The closing paragraph of every report.
export const NOT_CHECKED = [
  "This report covers only what alp-check observes from outside, with no credentials. It is not a statement that the implementation conforms: an implementation claims classes and passes the vectors that apply to it (Section 13.1), and the vectors, run through the implementation's own code, are how it checks its own logic (vectors/README.md).",
  "Not checked here: anything that needs a token (the tool list, tool results, the REST mirror's behaviour, sanitizing, DLP, the own-agent path); anything that needs the checker to act as a peer broker with its own domain and keys (signatures, pinning, audience, expiry, replay, receipts: acceptance steps 1 to 6, beyond the one probe whose sender's domain cannot exist); and everything not observable from outside (ledgers, the security event stream, grants, ratification, kill switches, retention, organization policy).",
];
