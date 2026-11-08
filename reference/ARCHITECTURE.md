# Reference broker: architecture

This is the reference home broker for the Agent Liaison Protocol (ALP) v0.1 draft. It is TypeScript on Node 22, run directly with Node's type stripping (no build step). This file is for the people and agents who build on it: the module layout, the exact interfaces, how a message moves, what is built and what is stubbed.

The specification in `../spec` and its JSON Schemas in `../schemas` are the source of truth for every protocol object: the core validates envelopes, control envelopes, receipts, ratification records, grants, domain documents, JWKS, org policies, ledger entries, security events and scope definitions with those files at runtime (`src/core/spec-schemas.ts`) and keeps no copies, so the reference cannot drift from the spec. `ALP_SCHEMA_DIR` overrides the location.

Everything under `reference/` (this broker, its tests, migrations, deployment files, Dockerfile and demo) is source-available under the Functional Source License, Version 1.1, ALv2 Future License (FSL-1.1-ALv2, [LICENSE.md](LICENSE.md)): free for any organization to use, modify and run for itself, but not to be made available to others in a commercial product or service that substitutes for it or offers substantially similar functionality; each version becomes Apache-2.0 two years after it is first published. The specification, schemas and vectors have their own licenses, under which anyone can implement ALP in a broker of their own ([README](../README.md#license)).

## Run it

```
npm ci               # exact pins, see "Dependencies"
npm test             # node --test over src/**/*.test.ts: unit, integration, HTTP and every conformance vector
npm run typecheck    # tsc --noEmit (TypeScript 6.0.3)
npm run check        # both; CI runs both, as separate steps
npm run demo         # the whole story over real HTTP (ports 47166-47176): MCP clients, OAuth, federation, web view
npm run demo:federation  # federation over real localhost HTTP (ports 47180-47185): numbered transcript
npm run demo:core    # the same story in one process, no HTTP (fast)
npm run dev          # the development broker for tests with real agents: example.org + test identities (src/dev.ts)
npm run preflight    # scripted SDK clients against a running dev broker's PUBLIC_URL (src/mcp/preflight.ts)
npm start            # a configured broker (ALP_CONFIG=deploy/config.example.json); see ../SELF-HOST.md
npm run migrate      # apply migrations/ to DATABASE_URL (npm start does it too)
npm run invite       # invitations for a broker that signs people in by invite (a hosted broker; needs DATABASE_URL)
npm run hosted-keys -- ./hosted-secrets.json  # write ALP_OAUTH_KEYS and ALP_KEYRING_KEY to a new 0600 file
npm run verify-ledger -- a.json [b.json]  # check exported ledgers offline: each chain, and two people's ledgers against each other
```

`npm test` runs the Postgres suites (the store, the binding state, row-level security, the hosted web view) on PGlite: Postgres compiled to WebAssembly, run inside the test process behind a small wire-protocol bridge (`src/storage/pglite-bridge.ts`), so no database server is installed or started. `ALP_TEST_POSTGRES_URL=postgres://... npm test` runs them against a real database instead.

Requires Node 22.18 or later (type stripping on by default). Code rules that make type stripping work, enforced by `tsconfig.json`:
- erasable syntax only: no `enum`, no `namespace`, no constructor parameter properties;
- relative imports end in `.ts`; type-only imports use `import type`;
- strict types, `noUncheckedIndexedAccess`, no `any`.

## Module layout

| Path | What it holds | Status |
|---|---|---|
| `src/core/protocol.ts` | The protocol's name in one place: display name, `alp` id and version field, `alp:` address scheme, `alp.` scope prefix, `alp-` typ prefix, `alp.json`, `_alp`, `alp_` tool prefix. | built |
| `src/core/types.ts` | Protocol and record types, mirroring the spec schemas. | built |
| `src/core/spec-schemas.ts`, `ajv.ts` | Ajv 2020-12 over `../schemas` (by each file's own `$id`), formats, the `x-alp-text` keyword. | built |
| `src/core/jcs.ts`, `hash.ts` | RFC 8785 canonicalization (own implementation, tested against the RFC's vectors); `sha256:` hashes of JCS. | built |
| `src/core/keys.ts`, `jws.ts` | Ed25519 key ring per purpose (`alp_use`): generate, load, next key, rotate, prune, JWKS, pins (kid = RFC 7638 `jkt`). Detached JWS over JCS, one `typ` per object, algorithm taken from the key. | built |
| `src/core/envelope.ts` | Sign and verify envelopes (`alp-envelope+jws`), control envelopes (`alp-control+jws`), receipts, ratification records. | built |
| `src/core/address.ts`, `pointers.ts`, `ids.ts`, `clock.ts` | Addresses (`alp:ana@example.org`), RFC 6901 pointers and patterns, monotonic ULIDs, the Clock. | built |
| `src/core/domain.ts` | Domain documents: validation, serial rule, one home broker per address, JWKS pinning, `revoked_jkt`, well-known URLs, TXT record, fetch limits. | built |
| `src/core/scopes/` | Scope registry over the spec's `schemas/scopes`: body validators, `x-alp-text` free-text pointers, classification labels (org overrides first), suggested fields, limits schema. | built |
| `src/core/policy/org-policy.ts` | Private org policy: principal refs (`@org`, `group:`, `alp:*@domain`, `*`), label patterns, federation and connection-request lists, client allow-list, delivery minimums, kill switches. | built |
| `src/core/policy/evaluate.ts` | The evaluator both sides run; the single generic code a recipient returns. | built |
| `src/core/policy/dlp.ts` | DLP hook contract, timeout and fail-closed runner, the sample regex DLP. | built |
| `src/core/relationships.ts` | Effective terms (consent grant, org default with forward/reverse, narrowing, revocation), explicit free-text naming, grant signing, quiet hours. | built |
| `src/core/threads.ts`, `ratification.ts`, `connections.ts` | Thread state machine (spec 9.2, 9.3): threads are conversations; each scope's `starts`, `replies` and `committer`, the types each state accepts, follow-ups, an accept or counter only to the other side's latest proposal, how threads end (what prolongs them, which declines close them), the thread limit (`MAX_THREAD_MESSAGES`, 200) and unexpired ratifications for a commit; terms hashes, standing-grant limits; connection request states. | built |
| `src/core/ledger.ts` | Per-principal ledger chained over entry digests, a random salt in each entry, payloads apart (`payload_hash`), verification, cross-check. | built |
| `src/core/security-events.ts` | OCSF-mapped security events (3002, 6003, `detail` profile), memory and JSONL sinks. | built |
| `src/core/content.ts`, `notify.ts`, `identity.ts` | Agent-facing content shaping (markup stripped, URLs defanged); notifications and web-view links; the dev IdP (test identities). | built |
| `src/core/windows.ts` | Rate and replay windows outside the core's own checks (failed sign-ins, OIDC sign-ins started, registrations, client metadata fetches, requests to the connector sign-in page and the web view), over the Store's `recordOnce` and `hitRateLimit`: this process's memory by default, the Postgres store for a hosted broker. | built |
| `src/core/interfaces.ts`, `api.ts`, `broker.ts` | The seams, the Broker API, and the Broker. | built |
| `src/storage/memory.ts`, `file.ts` | Memory store; file store (atomic writes, keys in a separate 0600 file). One conformance suite runs on both. | built |
| `src/federation/in-process.ts`, `static-resolver.ts` | In-process transport and a map-backed resolver (tests, demo, and the contract the HTTPS versions keep). | built |
| `src/federation/fetcher.ts`, `net-guard.ts`, `strict-json.ts` | The hardened fetcher (443 only, public addresses only, pinned connect, no redirects, 200 and JSON only, 64 KiB, 5 s, the dev host map) and strict I-JSON parsing. | built |
| `src/federation/resolver.ts` | `HttpsDomainResolver`: both document locations, a max_age cache that is never served stale, rollback refusal, failure cache, discovery rate limit, remembered `revoked_jkt`, the TXT hint, JWKS caching. | built |
| `src/federation/inbox.ts`, `server.ts` | The federation inbox and JWKS endpoints (`FederationServer`), `DomainAuthorityServer`, listen and close helpers. | built |
| `src/federation/transport.ts` | `HttpsFederationTransport`: retries with backoff and `Retry-After`, idempotency by id, TTL. | built |
| `src/federation/http-signatures.ts` | Optional RFC 9421 request signatures and RFC 9530 Content-Digest (the spec 12.2.2 profile). | built |
| `src/federation/domain-authority.ts` | Domain documents that pin each broker's keys; the same-origin endpoint rule. | built |
| `src/federation/http-world.ts`, `testing.ts` | The three-broker world over localhost HTTP (tests and `demo:federation`); test helpers. | built |
| `src/oauth/` | The client binding's OAuth 2.1 authorization server (oidc-provider 9.13.3), the connector sign-in page, protected-resource metadata and token verification, personal access tokens, and the binding's own state behind the async `BindingStore` seam (`state.ts`: memory, or `binding.json`; Postgres in `src/storage/postgres-binding.ts`). Stored payloads leave out every id that is a credential (`ID_IS_SECRET`: a refresh token's or code's id is the token, a session's its cookie); `sources.ts` keys per-source limits, an IPv6 /64 counting as one source. | built |
| `src/oauth/oidc.ts`, `oidc-signin.ts` | Sign-in through the organization's OpenID provider (generic, or Microsoft Entra ID): the relying party (discovery, key set and token endpoint through the hardened fetcher, ID token checks, the iss + sub or tid + oid binding, the address alias, group claims and the overage refusal) and the plumbing the sign-in page and the web view share (login transactions bound to the browser, the connector hand-off, sealed provider refresh tokens, the re-check at refresh), all kept in the `BindingStore`. | built; tested against a standard OpenID provider (oidc-provider as the stand-in, `oidc-testkit.ts`), and once against a live Entra tenant with test users ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)) |
| `src/mcp/` | The seven tools over MCP Streamable HTTP (2026-07-28 and 2025-era initialize, JSON responses) and the REST mirror; the untrusted-content wrapper and the spec 12.1.6 sanitizer; `npm run preflight`. | built |
| `src/web/` | The person's web view (connections, ratification, messages, agents, personal access tokens, grants, ledger) and the console-and-outbox notifier; on a public origin (`public`), invite sign-in (`invites.ts`), passkeys over the terms' hash (`passkeys.ts`, @simplewebauthn/server) and the other spec 12.5.2 protections. `webauthn-testkit.ts` is a software authenticator for the tests. | built |
| `src/server.ts`, `src/dev-world.ts` | The HTTP broker: the core plus the client binding on two listeners (public and loopback); the development world (example.org policy, test identities). | built |
| `src/demo/world.ts` | The fictional in-process world (example.org Local broker, partner.example, outside.example, a rogue broker) for the core tests and `demo:core`. | built |
| `src/dev.ts`, `src/demo/federation.ts`, `src/demo/core.ts` | Script entry points (`npm run dev`, `npm run demo:federation`, `npm run demo:core`). | built |
| `src/demo/index.ts`, `src/demo/http-world.ts` | `npm run demo`: one person's three agents of different trust (step 0), then eight steps between people, over real HTTP. Every broker runs the client binding and the federation inbox on one origin; agents are MCP SDK clients that sign in through OAuth (client ID metadata documents, PKCE, the sign-in page); people use the web view over HTTP. | built |
| `src/conformance/` | Every file in `../vectors` run through the reference's own code paths (`vectors.test.ts`), with the vectors' world as reference brokers (`vector-world.ts`, TEST-ONLY keys). | built |
| `src/core/scopes/semantics.ts` | The core scopes' semantic rules (spec 7.8): a meeting accept fixes a proposed slot; availability answers stay inside the window. | built |
| `src/main.ts`, `deploy/`, `Dockerfile` | `npm start`: a broker configured from JSON and the environment (file or Postgres store, Local or federated; test identities, invites or the organization's OpenID provider; the web view on loopback, or on the public origin with invites), for SELF-HOST.md and hosted deployments. `deploy/VERCEL-SUPABASE.md` is the hosted deployment note, `deploy/OPERATOR-STATEMENT.md` the operator statement template. | built |
| `src/verify-ledger.ts` | `npm run verify-ledger`: checks ledgers exported from the web view offline, with `verifyLedger` and `crossCheckEntries` (`src/core/ledger.ts`). | built |
| `src/policy-files.ts`, `src/limits-env.ts` | The policy files `npm start` installs and their reload on `SIGHUP`, each file on its own; the message rate limits read from the environment (`ALP_DEFAULT_RATE_LIMIT`, `ALP_OWN_AGENT_RATE_LIMIT`). | built |
| `src/invite.ts`, `src/hosted-keys.ts` | `npm run invite` (create, list, revoke invitations) and `npm run hosted-keys` (the two environment secrets of a hosted broker, written to a 0600 file). | built |
| `src/storage/postgres.ts`, `migrate.ts`, `migrations/` | The Postgres store (same conformance suite), its SQL migrations (each applied once under a transaction-level advisory lock; 007 keeps the notifications that wait for quiet hours to end) and `npm run migrate`; key rings sealed with AES-256-GCM under `ALP_KEYRING_KEY`. | built |
| `src/storage/postgres-binding.ts`, `migrations/002`-`006` | The client binding's state in Postgres (the same conformance suite as memory and file: `binding-store.test.ts`), the web view's tables, and row-level security on every table with no policy. Migration 005 removes raw token ids stored before the adapter left them out; 006 allows one live principal per address and per identity. | built |
| `src/storage/pglite-bridge.ts` | Test support: PGlite behind a Postgres wire-protocol socket on loopback, one backend session shared between client connections the way a transaction pooler would. | built (tests only) |

## Profiles

One `Broker` class runs every profile. What differs is configuration.
- **Local** (the default, spec 3.3): one organization's broker for its own people. It needs no domain document, no published policy and no federation listener. Envelopes are still signed (for ledger integrity), and acceptance steps 1 and 3 are met from local state: a local sender must be signed by this broker with its own principal_id.
- **Federated organization brokers**: the same, plus a domain document and the federation inbox.
- **Hosted**: the same code with the Postgres store, the client binding's state and the rate windows in Postgres (so any number of instances given the same `ALP_OAUTH_KEYS` serve it; the federation inbox's per-address limit and request-signature nonces stay per instance), sign-in by invite, and the web view on the public origin behind passkeys (`deploy/VERCEL-SUPABASE.md`).

Org policy is private local configuration (`BrokerOptions.policies`), never published. `setOrgPolicy` (operator only) replaces it at once; a policy needs a higher `serial`. Its `blocked` lists are the kill switches. Its `clients` list ranks every connected agent at the moment it reads, sends or receives (`ranked`, spec 5.4): a lower attestation or class applies at once, a higher one at the agent's next sign-in, and a personal access token is never above `self` and `business`. In `enforce` mode a client the list doesn't name is refused everywhere (`clientRefused`): sign-in, reads, sends, token refresh, the resource server and, for `pat`, minting on the web view.

## How a message moves

**Sending** (`send` → `prepareSend` → `sendAs`), all at the sender's home broker, in the order of spec 6.6, stopping at the first failure. `evaluateSend` runs the same steps without writing anything (the sender-side vectors use it).
1. S1: authenticate the delegate (an active delegate of an active principal, with the token's `client_id`); a payload `from` must equal the caller's principal (`identity_mismatch`); the address, scope and type; sender labels are additions only, at most 4, each one the scope or the policy names exactly (a pattern `x.*` names `x` only).
2. S2: kill switches (principal, delegate, client, scope, recipient domain); the client allow-list (`client_not_allowed` in enforce mode, a security event either way).
3. S3: the thread: what may start a thread, what may reply to what (`in_reply_to` must name a message in the thread, from either side, whose thread a reply joins when it names none; `in_reply_to_hash` is filled in; an accept or a counter answers the other side's latest proposal), what may follow up without naming a message, what the thread's state accepts, the thread limit, `terms_hash` on accept and commit, and for a commit both ratification hashes, unexpired.
4. S4: the organization's deny rules: the federation list, then the classification rules in order (`reject` fails with the leaves and the rule id; `redact` marks leaves).
5. S5: effective terms (spec 6.6.1: the explicit grant and the organization default, intersected when both apply), the type, field coverage (free text only by exact pointer), `redaction`.
6. S6: marked leaves removed (emptied containers pruned), the scope's schema and its semantic rules (an `alp.availability/1` inform keeps to the window of the request of its recipient's that it answers, or else of the latest one: `windowRequestId`, from the thread's history). S7: DLP on every remaining free-text leaf and the note.
7. S8: the decision (`labels`, `constraints` from `delivery_minimums`, `decision.policy_ids` = `<domain>#<serial>` plus DLP verdict ids); the rate limit; hold for review (spec 6.12: the draft waits for the person on the web view, `held_for_review`, and nothing is signed. A held message that would open a thread gets its thread id reserved (`opens_thread`); the thread starts when the person approves it. On approval the broker evaluates the draft again in full (`reviewHeld`), in that reserved thread for an opener, and the held record ends `sent`, or `refused` with the code sending answered; it is otherwise `pending`, `discarded` or `expired`. Every decision leaves `pending` through `claimHeldOutbound`, one atomic step, so of two decisions at once one acts; an approval holds the record as `sending` until the outcome is recorded. If the approval fails on the way (a store or connection error), the record leaves `sending` too: with what sending answered, and its `released` entry, when only recording that failed (a write that landed though it reported a failure is read back, and the ledger is searched first, so there is one `released` entry); otherwise back to `pending` when the envelope's `sent` entry wasn't written yet (nothing left), and `refused` with `undeliverable`/`internal` and the envelope id after it, since the message may have arrived. Only a broker that stops first leaves it `sending`, so it is never sent twice. Approving and discarding both write `released` to the ledger); otherwise sign (`aud` = the recipient's home broker), write `sent` to the ledger, deliver, verify the receipt (addressed to this broker, from the recipient's home broker, signed with a pinned key, about this envelope), and write a `receipt` entry with the receipt's hash and the recipient's entry hash.

**Receiving** (`acceptInbound` = `authenticateInbound`, steps 0 to 6, then steps 7 to 11), at the recipient's home broker, which never relies on the sender's broker having done its part. Every refusal names its step (`InboundResult.step`), and the conformance vectors check it.
- 0: structure (`checkEnvelopeStructure`: version, shape, schema, lifetime, at most 300 seconds in the future); `from.delegate` and `to.delegate`, when present, are delegate ids of `from.address` and `to.address`.
- 1: the sender domain's document lists `origin_broker`, and a key it pins for that broker (not revoked) verifies `broker_sig` (an unknown kid refetches the JWKS once). A sender who is a principal of this broker is checked against local state instead. Steps 0 and 1 answer with an unsigned error; later steps with a signed `refused` receipt.
- 2: the `typ` the shape requires. 3: `aud` is this broker, which is the recipient's home broker (its domain document decides; local state between two of its own principals). 4: at most 300 seconds past `expires_at`. 5: the replay window (to `expires_at` plus a grace period): an identical duplicate gets the original receipt and changes nothing (spec 10.3), one first refused for a retryable reason is evaluated again, and the same id with other content is refused as `replay` without replacing the original receipt. 6: `origin_broker` is the sender's home broker under the document.
- An unknown recipient: a connection request gets the same `accepted` receipt as any other (spec 6.2.2); a message is refused `not_accepted`.
- 7 to 10 (the evaluator, inbound): kill switches, the federation list and inbound classification rules; the relationship, the type and coverage (a stranger's message becomes a contact attempt: a connection request to the person, receipt `not_accepted`); the rate limit and the thread (a reply to a message this broker doesn't hold yet is refused `thread_state` with a retry hint, which the federation inbox sends as `Retry-After`); the schema and semantic rules, the availability window from this broker's own copy of the thread; inbound DLP. A recipient never alters a signed envelope: it accepts or refuses.
- 11: delivery constraints: one this broker can't honor is refused (`constraints_unsupported`); otherwise only qualifying agents see the message, and it is held for the person's web view when none qualifies, or until the grant's quiet hours end. A message whose `to.delegate` names no agent of the person's that can receive it (none active with that label, blocked, or its client refused) is held for the web view too (`held_reason: "to_delegate"`), never handed to the person's other agents; the receipt is the one any accepted message gets.
- Then `received` in the ledger (its hash goes in the receipt as `ledger_hash`), the signed receipt and the stored message, the same work whether or not the message waits for the person. A message that waits says where in its `received` entry (`ref`: `web_view`, or `until:` and the end of quiet hours; the ledger page shows it), so the ledger records the hold before the answer. Every entry carries a random salt (spec 11.4), so `ledger_hash` confirms no guess of what the entry says, the hold included. What a hold adds (the notification, which only notifies, and its rate-limit record) and the pushes with an opaque id run after the answer (decision 14). During the grant's quiet hours the notification waits until they end (a `DeferredNotice` in the store, sent by `sendDueNotices`).

Refusals tell the sender one generic code (`codeForSender`, spec 6.8) and never name the recipient's rules.

**Ratification** (spec 9.4): an `accept` (carrying `body.terms`) fixes `terms_hash = sha256(JCS(body.terms))`. Each side's broker then ratifies for its own person: by a standing grant if its limits cover the terms (method `standing-grant:<grant id>`), otherwise by a ratification request the person approves on the web view with a fresh sign-in. The broker signs a ratification record (`alp-ratification+jws`, with `terms_hash`, `principal_id`, method, `iat`, nonce, `aud` = the counterparty's home broker) and sends it in an `ack` with status `ratified`. A `commit` must carry the same `terms_hash` and both records' hashes, both records still valid at both brokers; it is single-use. In `agreed` the terms can't change: new terms need a new thread. The side that sent the accept ratifies within its own call; the side that received it does so once its answer is out (`afterAnswering`), because the accepting broker records its accept only when the receipt is back, and a ratification ack sent before then would find no agreed terms there. At most three open requests per counterparty. Declining sends `decline` (`ratification_declined`) and cancels the thread on both sides; when a thread leaves `agreed` without a commit, each side voids its person's pending requests for it (`voidRatifications`).

**Connections**: an agent can file a request; it reaches the person (their broker's page and a notification that only notifies), never the agent. On approval, the approver's grant is sealed by their fresh sign-in. The requester's grant becomes active at once if the person filed the request themselves; if their agent filed it, the grant is pending until the person seals it (`sealGrant`). An agent can never create, widen or seal a grant.

## The Broker API

`src/core/api.ts`. The authorization server, the MCP and REST bindings, the web view, the admin tool and the federation inbox call these.

```ts
export interface BrokerApi {
  readonly id: BrokerId;

  // Sign-in plumbing: the authorization server calls these after the person signs in and authorizes a client.
  registerPrincipal(input: RegisterPrincipalInput): Promise<PrincipalRecord>;
  registerDelegate(input: RegisterDelegateInput): Promise<DelegateRecord>;
  revokeDelegate(id: DelegateId): Promise<DelegateRecord>;
  getPrincipal(address: string): Promise<PrincipalRecord | null>;

  // Agent-facing (the MCP and REST tools).
  whoami(caller: DelegateCaller): Promise<WhoAmI>;
  contacts(caller: DelegateCaller): Promise<Contact[]>;
  /** Sender-side evaluation, then sign, then deliver (locally or by federation), then verify the receipt. */
  send(caller: DelegateCaller, input: SendInput): Promise<SendResult>;
  inbox(caller: DelegateCaller, query?: InboxQuery): Promise<InboxPage>;
  ack(caller: DelegateCaller, input: { envelope_ids: string[] }): Promise<{ acked: number }>;
  thread(caller: DelegateCaller, threadId: string): Promise<ThreadView>;
  requestConnection(caller: Caller, input: ConnectionRequestInput): Promise<ConnectionRequestResult>;

  // Human-facing (the broker's web view, or a native app's own UI). Approvals need a fresh step-up.
  messagesForPerson(caller: HumanCaller, query?: InboxQuery): Promise<InboxPage>;
  listConnections(caller: HumanCaller): Promise<ConnectionRequestRecord[]>;
  respondToConnection(caller: HumanCaller, input: ConnectionResponseInput): Promise<ConnectionRequestRecord>;
  listGrants(caller: HumanCaller): Promise<RelationshipGrant[]>;
  setGrant(caller: HumanCaller, input: GrantInput): Promise<RelationshipGrant>;
  /** Seal a pending grant (one an agent's connection request produced) after the person reviews it. */
  sealGrant(caller: HumanCaller, input: { counterparty: string }): Promise<RelationshipGrant>;
  revoke(caller: HumanCaller, input: RevokeInput): Promise<RelationshipGrant>;
  listRatifications(caller: HumanCaller): Promise<RatificationRequest[]>;
  ratify(caller: HumanCaller, input: RatifyInput): Promise<RatificationRequest>;
  ledger(caller: HumanCaller, query?: LedgerQuery): Promise<LedgerEntry[]>;
  ledgerPayload(caller: HumanCaller, seq: number): Promise<LedgerPayload | null>;
  verifyLedger(caller: HumanCaller): Promise<LedgerCheck>;

  // Operator (admin CLI or a loopback-only endpoint). Kill switches are the policy's `blocked` lists.
  setOrgPolicy(caller: AdminCaller, policy: OrgPolicy): Promise<void>;
  rotateKeys(caller: AdminCaller): Promise<{ active: string; pins: string[] }>;

  // Federation-facing: the federation inbox hands over the parsed JSON body.
  /** Signature, typ, aud, expiry, replay, home broker; then the recipient's rules; then store, ledger and a signed receipt. */
  acceptInbound(envelope: unknown, ctx?: InboundContext): Promise<InboundResult>;
  /** The broker's public JWKS, to serve at its jwks_uri. Every key in it must be pinned in the domain document. */
  jwks(): Jwks;
}
```

The `Broker` class adds, outside the interface: `authenticateInbound(raw)` (acceptance steps 0 to 6 alone), `evaluateSend(caller, input, { skipThreadChecks })` (the sender-side evaluation without side effects), `listHeld(human)` and `reviewHeld(human, { held, decision: "send" | "discard" })` (hold for review), and `recordSecurityEvent`.

Callers (`src/core/types.ts`). The client binding turns a verified token into a `DelegateCaller`; the web view turns a session into a `HumanCaller` and sets `auth` from the last sign-in (approvals need it to be under 5 minutes old).

```ts
/** An agent, authenticated to its own home broker (OAuth access token or personal access token). */
export interface DelegateCaller {
  kind: "delegate";
  principal: Address;
  delegate: DelegateId;
  client_id: string;
}

/** The person, signed in to the broker's own page (or a native app's own UI). */
export interface HumanCaller {
  kind: "human";
  principal: Address;
  /** How and when the person last authenticated; approvals need a fresh step-up. */
  auth?: { method: SealMethod; at: Timestamp };
}

/** The operator (admin CLI or loopback-only admin endpoint). */
export interface AdminCaller {
  kind: "admin";
  operator: string;
}
```

Inputs and results (`src/core/api.ts`):

```ts
export interface RegisterPrincipalInput {
  address: string;
  /** The IdP identity (iss + sub). Reassigning an address to another identity creates a new principal. */
  identity: { iss: string; sub: string };
  display_name?: string;
  contact?: { email?: string; sms?: string };
  human_fallback?: boolean;
  claims?: { issuer: string; name: string; value: string }[];
}

export interface RegisterDelegateInput {
  principal: string;
  /** `muse`, `claude`, `dot`... Reserved: broker, admin, web. */
  label: string;
  kind?: "bridged" | "native";
  client_id: string;
  /** Defaults from the org's `clients` rule for this client, else self / consumer. */
  attestation?: Attestation;
  class?: DelegateClass;
}

export interface SendInput {
  to: string;
  to_delegate?: string;
  scope: ScopeId;
  type: MessageType;
  body: JsonObject;
  note?: string;
  thread?: string;
  in_reply_to?: string;
  expires_in_seconds?: number;
  /** Optional sender claim; it must equal the caller's own principal. */
  from?: string;
  /** Labels to add to the ones the broker computes (spec 6.5: additions only). */
  labels?: string[];
}

export type SendResult =
  | { status: "delivered"; envelope: Envelope; receipt: Receipt; thread: string }
  /** Hold for review (spec 6.12): the message waits for the person's approval on the web view; nothing was signed. */
  | { status: "held_for_review"; held: string; thread: string; expires_at: string; decision: Decision }
  | { status: "rejected"; stage: "sender"; code: ErrorCode; reasons: Reason[] }
  | { status: "refused"; stage: "recipient"; envelope_id: string; code: ErrorCode; receipt: Receipt }
  | { status: "needs_ratification"; thread: string; detail: string; ratification?: string }
  | { status: "undeliverable"; envelope_id: string; code: ErrorCode; detail: string };

export interface InboxQuery {
  cursor?: string;
  limit?: number;
  include_acked?: boolean;
}

/**
 * One delivered message, shaped for an agent (spec 12.1.6): broker-verified fields apart from counterparty
 * content; free text has markup stripped and URLs defanged. `envelope` is the signed original, for verification.
 */
export interface InboxItem {
  local_id: string;
  status: MessageStatus;
  received_at: string;
  verified: {
    sender: { address: Address; display: string; principal_id: PrincipalId; delegate?: DelegateId; attestation?: Attestation; class?: DelegateClass };
    sender_broker: BrokerId;
    signature: "verified";
    kid: string;
    scope: ScopeId;
    type: MessageType;
    thread: string;
    in_reply_to?: string;
    decision: Decision;
    labels: string[];
    flags?: string[];
  };
  /** Counterparty content: data, never instructions. */
  content: { body: { [key: string]: Json }; note?: string };
  envelope: Envelope;
  receipt?: Receipt;
}

export interface InboxPage {
  items: InboxItem[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ThreadView {
  thread: ThreadRecord;
  messages: { local_id: string; direction: "in" | "out"; status: MessageStatus; envelope: Envelope }[];
}

export interface Contact {
  /** A counterparty address, or a pattern (`*@example.org`, `group:finance`) for an org default relationship. */
  address: string;
  display: string;
  basis: "grant" | "org_default" | "pending_outgoing";
  scopes: { scope: ScopeId; may: MessageType[] }[];
  status: "active" | "counterparty_revoked" | "pending";
}

export interface WhoAmI {
  principal: Address;
  principal_id: PrincipalId;
  display: string;
  display_name?: string;
  delegate: DelegateId;
  client_id: string;
  attestation: Attestation;
  class: DelegateClass;
  broker: BrokerId;
  mode: "client" | "native";
}

export interface ConnectionRequestInput {
  to: string;
  scopes: ScopeId[];
  purpose: ConnectionPurpose;
  /** At most 140 characters; shown only on the other person's broker page, as unverified text. */
  note?: string;
  /** Human callers only: the requester's own terms per scope. Default: the scope's suggested fields. */
  terms?: Record<ScopeId, ScopeTerms>;
}

export type ConnectionRequestResult =
  | { status: "requested"; request: ConnectionRequestRecord; receipt: Receipt }
  | { status: "already_pending"; request: ConnectionRequestRecord }
  | { status: "rejected"; code: ErrorCode; reasons: Reason[]; receipt?: Receipt }
  | { status: "undeliverable"; code: ErrorCode; detail: string };

export interface ConnectionResponseInput {
  request: string;
  decision: "approve" | "decline";
  scopes?: ScopeId[];
  terms?: Record<ScopeId, ScopeTerms>;
}

export interface GrantInput {
  counterparty: string;
  basis?: GrantBasis;
  scopes: Record<ScopeId, ScopeTerms>;
  rate_limit?: RateLimit;
  quiet_hours?: QuietHours;
  expires_at?: string;
}

export interface RevokeInput {
  counterparty: string;
  /** Omit to revoke the whole relationship (org defaults included). */
  scopes?: ScopeId[];
}

export interface RatifyInput {
  request: string;
  decision: "approve" | "decline";
}

export interface LedgerQuery {
  after_seq?: number;
  limit?: number;
}
```

## The seams

`src/core/interfaces.ts`: Store (memory, file and Postgres), DomainResolver and FederationTransport (federation), IdentityVerifier (the dev IdP, invites, or the organization's OpenID provider in `src/oauth/oidc.ts`), Notifier and LinkBuilder (human fallback), AgentPush. Outside the core: the client binding's `BindingStore` (`src/oauth/state.ts`; memory, file and Postgres) and `Windows` (`src/core/windows.ts`, the Store's two window methods).

```ts
// The seams. The broker core depends only on these; storage, federation, identity, notification and security
// events are swappable. Implementations: src/storage (Store), src/federation (FederationTransport, DomainResolver),
// src/oauth (IdentityVerifier and the authorization server), src/web + core/notify.ts (Notifier, LinkBuilder),
// core/security-events.ts (SecurityEventSink).


export type { Clock } from "./clock.ts";
export type { SecurityEventSink } from "./security-events.ts";

// ---------------------------------------------------------------------------------------------
// Store: memory and file now, Postgres for the hosted broker. Each method is atomic on its own; records go in
// and come out as copies.

export interface MessageQuery {
  direction?: "in" | "out";
  /** Exclusive cursor: local_id greater than this. */
  after?: string;
  limit: number;
  thread?: string;
  status?: MessageStatus[];
  /** Only messages this delegate hasn't acknowledged. */
  unackedBy?: DelegateId;
  /** Only messages addressed to the principal in general or to this delegate. */
  forDelegate?: DelegateId;
  /**
   * When the binding of the delegate in `forDelegate` and `unackedBy` started (spec 5.4): a message addressed to it
   * counts only if it was stored at or after this time, and an acknowledgement only if it was made at or after it.
   * Earlier ones belong to an earlier binding with the same label.
   */
  bindingSince?: Timestamp;
}

export interface Store {
  readonly kind: string;

  /** The active principal that currently holds this address (aliases move; principal_ids never do). */
  getPrincipal(address: Address): Promise<PrincipalRecord | null>;
  getPrincipalById(id: PrincipalId): Promise<PrincipalRecord | null>;
  getPrincipalByIdentity(iss: string, sub: string): Promise<PrincipalRecord | null>;
  putPrincipal(rec: PrincipalRecord): Promise<void>;
  listPrincipals(): Promise<PrincipalRecord[]>;

  getDelegate(id: DelegateId): Promise<DelegateRecord | null>;
  putDelegate(rec: DelegateRecord): Promise<void>;
  listDelegates(principal: Address): Promise<DelegateRecord[]>;

  /** One grant per (owner, counterparty). */
  getGrant(principal: Address, counterparty: Address): Promise<RelationshipGrant | null>;
  putGrant(grant: RelationshipGrant): Promise<void>;
  listGrants(principal: Address): Promise<RelationshipGrant[]>;

  getRevocation(principal: Address, counterparty: Address): Promise<CounterpartyRevocation | null>;
  putRevocation(rec: CounterpartyRevocation): Promise<void>;

  getConnection(principal: Address, id: string): Promise<ConnectionRequestRecord | null>;
  putConnection(rec: ConnectionRequestRecord): Promise<void>;
  listConnections(principal: Address): Promise<ConnectionRequestRecord[]>;

  /** Insert or replace, keyed by (principal, direction, envelope.id). */
  putMessage(rec: MessageRecord): Promise<void>;
  getMessage(principal: Address, direction: "in" | "out", envelopeId: string): Promise<MessageRecord | null>;
  /** Ascending local_id. */
  listMessages(principal: Address, q: MessageQuery): Promise<MessageRecord[]>;

  /** A notification that waits until the grant's quiet hours end (spec 6.7). */
  putDeferredNotice(rec: DeferredNotice): Promise<void>;
  /**
   * Removes and returns the deferred notifications due at `now` (`due_at` at or before it), earliest first, at most
   * `limit`, in one atomic step: of several brokers sharing the store, each notification goes to one.
   */
  takeDueNotices(now: Date, limit: number): Promise<DeferredNotice[]>;

  getThread(principal: Address, id: string): Promise<ThreadRecord | null>;
  putThread(rec: ThreadRecord): Promise<void>;

  /** Outbound messages held for their sender's review (spec 6.12). */
  putHeldOutbound(rec: HeldOutbound): Promise<void>;
  /**
   * Replaces a held message's record only if the stored one is still in state `from` (default `pending`), in one
   * atomic step; true when this call replaced it. Every decision on a held message goes through here, so of two at
   * once exactly one takes effect; an approval that failed leaves `sending` the same way.
   */
  claimHeldOutbound(next: HeldOutbound, from?: HeldOutbound["state"]): Promise<boolean>;
  getHeldOutbound(principal: Address, id: string): Promise<HeldOutbound | null>;
  listHeldOutbound(principal: Address): Promise<HeldOutbound[]>;

  getRatificationRequest(id: string): Promise<RatificationRequest | null>;
  putRatificationRequest(rec: RatificationRequest): Promise<void>;
  listRatificationRequests(principal: Address): Promise<RatificationRequest[]>;

  /** Receipts this broker issued, keyed `${origin_broker}|${envelope id}`. */
  putReceipt(key: string, receipt: Receipt): Promise<void>;
  getReceipt(key: string): Promise<Receipt | null>;

  /**
   * Append to a principal's ledger (keyed by principal_id). `build` gets the head and returns the entry (and its
   * payload, stored apart); read-head + build + insert is atomic (a transaction with a row lock in Postgres).
   */
  appendLedger(principalId: PrincipalId, build: (head: LedgerHead | null) => { entry: LedgerEntry; payload?: LedgerPayload }): Promise<LedgerEntry>;
  listLedger(principalId: PrincipalId, q?: { afterSeq?: number; limit?: number }): Promise<LedgerEntry[]>;
  getLedgerPayload(principalId: PrincipalId, seq: number): Promise<LedgerPayload | null>;
  /** Crypto-shredding stand-in: drop the payload; the chain still verifies. */
  eraseLedgerPayload(principalId: PrincipalId, seq: number): Promise<void>;

  /** Replay window: record `key` until `expiresAt`. False if already recorded and unexpired. Atomic. */
  recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean>;
  /** Sliding-window rate limit; counts the hit only when allowed. Atomic per key. `retryAfter`: whole seconds until the oldest hit leaves the window. */
  hitRateLimit(key: string, now: Date, windowSeconds: number, limit: number): Promise<{ allowed: boolean; count: number; retryAfter: number }>;

  /** Private key material. File store: a separate 0600 file. Hosted: an encrypted column or a KMS. */
  getKeyRing(name: string): Promise<StoredKeyRing | null>;
  putKeyRing(name: string, ring: StoredKeyRing): Promise<void>;

  close(): Promise<void>;
}

// ---------------------------------------------------------------------------------------------
// Federation (src/federation)

export interface DomainResolver {
  /**
   * The validated domain document (checkDomainDocument), fetched only from https://<domain>/.well-known/alp.json
   * or https://alp.<domain>/.well-known/alp.json through the hardened fetcher (443 only, no redirects,
   * 200 only, at most 64 KiB, 5 s, no private or loopback addresses; dev host map for localhost). Cached up to max_age;
   * a lower serial is refused; brokers and keys are never used past max_age even when a refresh fails, while de-listings
   * keep applying for RESTRICTION_PERSIST_SECONDS. Throws AlpError("discovery_failed") and never echoes fetch errors.
   */
  domainDocument(domain: string, opts?: { refresh?: boolean }): Promise<DomainDocument>;
  /** A broker's published JWKS (raw; the core pins it against the domain document). `refresh` bypasses the cache once. */
  jwks(jwksUri: string, opts?: { refresh?: boolean }): Promise<Jwks>;
}

export interface DeliveryTarget {
  broker: BrokerId;
  inbox: string;
}

/** Transport metadata. Authentication comes from the signed envelope itself (aud + pinned keys), not the request. */
export interface InboundContext {
  remote?: string;
}

/** What a recipient broker answers: a signed receipt (the envelope's signature verified), or a plain refusal. */
export type InboundResult =
  | { kind: "receipt"; receipt: Receipt; step?: number; duplicate?: true }
  | { kind: "refused"; status: number; code: ErrorCode; message: string; step?: number };

export type DeliveryResult = InboundResult | { kind: "unreachable"; message: string };

export interface FederationTransport {
  /** HTTPS POST of the signed envelope (JSON) to the target's inbox; maps the answer. Never throws for remote failures. */
  deliver(target: DeliveryTarget, envelope: AnyEnvelope): Promise<DeliveryResult>;
}

// ---------------------------------------------------------------------------------------------
// Identity (src/oauth): who the signing-in person is. The dev IdP (core/identity.ts: test identities), or the
// organization's OpenID provider (src/oauth/oidc.ts, e.g. Entra). Principals bind to iss + sub (for Entra: the tenant
// issuer + oid), never to email or upn.

export type IdentityAssertion = { kind: "dev"; username: string; secret?: string } | { kind: "oidc"; id_token: string; nonce?: string };

export interface VerifiedIdentity {
  address: Address;
  display_name?: string;
  method: "dev" | "oidc";
  iss: string;
  sub: string;
  claims?: { issuer: string; name: string; value: string }[];
  verified_at: string;
}

export interface IdentityVerifier {
  readonly id: string;
  /** Throws AlpError("identity_mismatch") when the assertion doesn't verify. */
  verify(assertion: IdentityAssertion): Promise<VerifiedIdentity>;
  listTestIdentities?(): { username: string; address: Address; display_name?: string }[];
}

// ---------------------------------------------------------------------------------------------
// People: notifications only notify (spec 12.5.1). Broker-generated text only; links only to the broker's
// own origin behind full sign-in; no link, code or reply acts.

export type NotificationKind = "connection_request" | "connection_decided" | "ratification_needed" | "ask_human" | "message_waiting" | "message_held";

export interface HumanNotification {
  principal: Address;
  kind: NotificationKind;
  channel: "email" | "sms";
  to: string;
  subject: string;
  text: string;
  link: string;
  at: string;
}

export interface Notifier {
  notify(n: HumanNotification): Promise<void>;
}

/** Paths the web surface (src/web) serves. No personal data in them. */
export interface LinkBuilder {
  connection(id: string): string;
  ratification(id: string): string;
  message(envelopeId: string): string;
  /** An outbound message held for the person's review (spec 6.12). */
  held(id: string): string;
  ledger(): string;
}

/** Push for agents whose platform accepts webhooks: an opaque id only; the agent fetches the inbox. */
export interface AgentPush {
  push(delegate: DelegateRecord, opaqueRef: string): Promise<void>;
}
```

The Clock (`src/core/clock.ts`; `systemClock`, and `ManualClock` for tests):

```ts
/** All time in the broker comes from a Clock, so tests can move time. */
export interface Clock {
  now(): Date;
}
```

Security events (`src/core/security-events.ts`; `MemorySecurityEvents`, `JsonlSecurityEvents`):

```ts
export interface SecurityEventSink {
  emit(event: SecurityEvent): Promise<void>;
}
```

The DLP hook (`src/core/policy/dlp.ts`; `runDlp` applies the timeout and fails closed unless the org set `on_error: allow`; `SampleDlp` is the sample):

```ts
export interface DlpInput {
  principal_id: PrincipalId;
  principal: Address;
  counterparty: Address;
  direction: "outbound" | "inbound";
  scope: ScopeId;
  labels: string[];
  /** Envelope-relative pointer: `/note` or a free-text field. */
  pointer: string;
  text: string;
}

export type DlpVerdict =
  | { verdict: "allow"; id?: string }
  | { verdict: "notify"; id: string }
  | { verdict: "block"; id: string; categories?: DlpCategory[] }
  | { verdict: "redact"; id: string; spans: [number, number][] }
  | { verdict: "require_justification"; id: string };

export interface DlpHook {
  readonly id: string;
  check(input: DlpInput): Promise<DlpVerdict>;
}
```

Constructing a broker (`src/core/broker.ts`):

```ts
export interface BrokerOptions {
  /** The broker's HTTPS origin. */
  id: BrokerId;
  store: Store;
  keys: KeyRing;
  resolver: DomainResolver;
  transport: FederationTransport;
  notifier: Notifier;
  /** Private org policies for the domains this broker hosts. */
  policies?: OrgPolicy[];
  /** Domains whose principals this broker hosts. Default: the policies' domains. */
  domains?: string[];
  securityEvents?: SecurityEventSink;
  /** Base URL of the broker's web view. Default `${id}/web`. */
  webBaseUrl?: string;
  links?: LinkBuilder;
  clock?: Clock;
  scopes?: ScopeRegistry;
  dlp?: DlpHook;
  push?: AgentPush;
  limits?: Partial<BrokerLimits>;
  /** A message from a stranger becomes a connection request to the person. Default true. */
  strangerMessagesBecomeRequests?: boolean;
}
```

## The client binding (src/oauth, src/mcp, src/web)

Built. An agent reaches its person's home broker through one connector URL; no core interface changed. `src/server.ts` (`startBrokerServer`) wires it to a `Broker`; `npm run dev` runs it for the development world (a test with real agent products goes through a temporary tunnel to its public port; `npm run preflight` checks that path first).

**Endpoints.** The public listener (`PORT`, default 47110, bound to 127.0.0.1; a tunnel or reverse proxy exposes it) builds every absolute URL from `PUBLIC_URL`, which is also the OAuth issuer:
- `POST /mcp` (also `/mcp/`): the MCP server over Streamable HTTP with JSON responses. Requests that carry the 2026-07-28 envelope go to the SDK's `createMcpHandler` (stateless, `server/discover`); 2025-era requests (`initialize` first) go to a per-request stateless `WebStandardStreamableHTTPServerTransport`. One tool implementation serves both. Every request is authenticated before the SDK sees it; a present `Origin` must be the public origin.
- `POST /rest/{tool}`, `GET /rest/openapi.json`: the REST mirror (spec 12.1.9).
- `GET /.well-known/oauth-protected-resource/mcp` (and the root form, and the `/mcp/` form), `/.well-known/oauth-protected-resource/rest`: RFC 9728. `GET /.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`: the same RFC 8414 / OpenID document.
- `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/jwks`, `/oauth/userinfo`, `/oauth/revoke`: oidc-provider. `/interaction/:uid`: the connector sign-in and consent page.
- The person's web view runs on a second listener, loopback only (`WEB_PORT`, default 47111): `/web`, `/web/connections/:id`, `/web/ratifications/:id`, `/web/messages/:id`, `/web/ledger`, `/web/ledger.json` and POST-only actions. The public listener answers 404 under `/web`, unless the view is served there instead (`publicWeb`, below).

**OAuth** (`src/oauth/provider.ts`). Client ID metadata documents (oidc-provider's experimental `clientIdMetadataDocument`, acknowledged at draft-02), and the JWKS a `private_key_jwt` client names, are fetched through oidc-provider's fetch with the broker's own rules on top (spec 4.3): https on port 443 to a host name only, no redirects (`redirect: manual`), `Cache-Control: no-cache`, `Accept-Encoding: identity`, a JSON content type, at most 5 KiB for a metadata document and 64 KiB for a JWKS, and 2.5 seconds for the whole fetch, its body included. oidc-provider makes later requests for a client wait on the first fetch of its document or key set, and ends that fetch only through its own 2.5-second signal, which can leave a compressed body pending forever in Node's fetch (when it fires after the body's last bytes arrived but before they were decoded); so the broker reads every body itself under a deadline of its own (`withDeadline`), and cancels at once the body of a metadata document's answer other than 200, which oidc-provider doesn't read. oidc-provider refuses special-use addresses, but checks once connected rather than before connecting, as the federation's hardened fetcher does (spec 4.3 rule 2): the one rule this path meets only in part. Fetches of metadata documents are budgeted, 20 a minute per requester (an IPv6 /64 counting as one) and 200 in all, except for client ids an installed policy's list of agents names, which are fetched outside both budgets so that strangers can't stop them from signing in or refreshing; a document that failed (no complete answer within 2.5 seconds, not 200, too big, or not a JSON object naming its own URL) isn't fetched again for 120 seconds; oidc-provider caches only the ones that worked. A document may list redirect URIs only on its own host or loopback. Dynamic registration requires `application_type` (`ALP_DCR_REQUIRE_APPLICATION_TYPE=0` relaxes it). Redirect hosts besides loopback are an allow-list (default `claude.ai`, `chatgpt.com`); loopback matches with the port ignored (RFC 8252). Token endpoint methods: `none`, `private_key_jwt` (ChatGPT's preference), `client_secret_basic`, `client_secret_post`. PKCE S256 for every client; `iss` in every authorization response. Access tokens are ES256 JWTs (`typ: at+jwt`) for the canonical resource (`<PUBLIC_URL>/mcp` or `/rest`), 10 minutes, carrying `client_id`, `scope` and `alp_delegate`. Refresh tokens rotate on every use, and a reused one revokes the grant (`refresh_reuse` security event), except that a token rotated less than 30 seconds ago works exactly once more, for two overlapping refreshes; they are issued to every client registered for the refresh grant, not only on `offline_access` (oidc-provider drops `offline_access` without `prompt=consent`). A connector grant ends after 30 days for organization principals and 90 for others. DPoP and PAR are off. Every authorization asks the person to sign in again, so one browser can't silently authorize a second agent as the same person.

**Sign-in** (`src/oauth/interaction.ts`). Every POST to the page counts first against a per-source limit (120 a minute, an IPv6 /64 counting as one source), before any secret is checked or any sign-in started. Development: the dev IdP's test identities and a per-session secret. A hosted broker: the person's invite name and secret (scrypt, run off the event loop; the sign-in is recorded on the invite only while it is live, so a revocation that lands meanwhile refuses it), then their passkey (registered on their web view first), over a challenge that binds the client, the scopes and the redirect URI. Failed sign-ins pause after 10 in 15 minutes for one source address and identity, and after 100 in 15 minutes in all, counting only failures for identities that exist (made-up names never reach the backstop); the counts live in `windows` (memory, or Postgres for a hosted broker). The source address is the socket's, or Cloudflare's `CF-Connecting-IP` when the broker is reached only through a Cloudflare tunnel (`behindCloudflare`: `ALP_BEHIND_CLOUDFLARE=1`, and by default in `npm run dev` when PUBLIC_URL is a `trycloudflare.com` origin); dynamic registration is limited per source the same way. Approval registers the principal (iss + sub), binds the client as a delegate (label from the org's client registration, else the metadata document's host, else the operator's pre-registration (its registered `client_name`), else, for a dynamically registered client only, the name the person confirms; attestation from the org's rule, else `vendor` for a metadata document and `self` otherwise) and records the grant. The consent page names the client by where its name comes from (spec 5.6 item 5): a metadata document's host, the operator's pre-registration (`AuthServer.isPreRegistered`; "Registered with this broker by its operator"), or the client itself (dynamic registration, shown with "(unverified name)"). With the organization's OpenID provider, the next paragraph.

**Sign-in through the organization's OpenID provider** (`src/oauth/oidc.ts`, `oidc-signin.ts`; `identity.kind: "oidc"` in `npm start`). Built and tested against a standard OpenID provider (oidc-provider run in-process as the stand-in, `src/oauth/oidc-testkit.ts`, in `src/oauth/oidc.test.ts`), and once against a live Microsoft Entra tenant with test users, on November 8, 2026 ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)). The broker is a confidential client of the provider (client_secret_basic or client_secret_post; the secret comes from `ALP_OIDC_CLIENT_SECRET`). On the sign-in page, "allow" sends the person to the provider: the authorization code flow with PKCE (S256), `state`, `nonce` and, by default, `prompt=login`. The transaction is stored in the `BindingStore` (model `AlpOidcLogin`, 10 minutes, single use, its PKCE verifier sealed) and bound to the browser by a random cookie (SameSite=Lax, so it returns with the provider's redirect); sign-ins started there are limited to 30 per source per 10 minutes (an IPv6 /64 counting as one source), counted in `windows`, with no overall total that starts from many addresses could use up; the web view's sign-ins and step-ups count apart (30 per person or source, 3000 in all), so nothing started on the public page can block an approval. The provider returns to `<PUBLIC_URL>/oidc/callback`, which checks the transaction and the browser, the RFC 9207 `iss` (required when the provider advertises it), exchanges the code at the token endpoint (with `provider: "entra"`, this request and each refresh name the configured scopes again, which Entra's v2.0 token endpoint may require) and checks the ID token. The browser then returns to `/interaction/<uid>/oidc`, where oidc-provider's own interaction cookie proves it is the browser that started the authorization, and the steps above run. Discovery, the key set and the token endpoint go through the hardened fetcher (443, public addresses, no redirects, 64 KiB, 5 seconds; a provider on a private network isn't supported). The ID token's checks: an asymmetric algorithm (no `none`, no HMAC), a key from the provider's set (an unknown `kid` refetches the set, at most once a minute), the exact issuer, the broker's client id as the only audience (and `azp` when present), expiry and `iat` with 60 seconds of skew, a code exchange's token at most 10 minutes old, the nonce, and `auth_time` no earlier than the sign-in when a fresh sign-in was asked for. The principal binds to `iss` + `sub`; with `provider: "entra"`, to the tenant's v2.0 issuer (`https://login.microsoftonline.com/<tid>/v2.0`, which must be the issuer of the token's own `tid`, from a listed tenant) + `oid`. Never to email, `preferred_username` or `upn`: the address comes from a configured claim (`email` with `email_verified`, or Entra's `preferred_username`), as an alias on a domain the provider, or that tenant, may sign in for. A new address for the same binding moves the alias and keeps the `principal_id` (agents connected under the old address must reconnect, and what the reference keeps by address doesn't move with it); an address another binding held makes a new principal and ends the old one's relationships (spec 5.2). Entra guest accounts (an `idp` claim other than the issuer) are refused unless `allow_guests` is set. Group claims (`group_claims`, default `groups`, or `roles` for Entra) become the principal's claims, which the policy's claim-based groups match, in default relationships and classification rules alike: for the person, and for the counterparty when it is another active principal of this broker (at the recipient's side, only for an envelope this broker signed, for that `principal_id`); a counterparty from elsewhere has no claims here, so it is in no claim-based group (fail closed, spec 6.4); an overflowed group claim (a distributed claim: Entra's groups overage sends a link to Microsoft Graph instead of the list) refuses the sign-in with a reason that points to app roles. Refusals show the person a fixed sentence and a reason code, never the provider's text, and write a `token_refused` security event. It can't be combined with the web view on a public origin yet (below): `startBrokerServer` and `npm start` refuse that.

**The re-check at refresh** (spec 5.3, offboarding). With `refresh_check` (the default), the broker asks the provider for `offline_access` and refuses a connection when the provider issues no refresh token. The provider's refresh token is kept per connector grant (model `AlpIdpSession`, sealed with AES-256-GCM under a key derived from the authorization server's first cookie key, opened with a key from any of its cookie keys, and sealed again at each successful re-check, so a rotation that keeps the old cookie keys after the new one ends no connection; a session no key opens ends the connection with its own log line and event message). Whenever an agent's connection refreshes, `findAccount` refreshes at the provider first: a refusal (a disabled or deleted account, revoked sessions) revokes the whole connection, its live access tokens included; a new ID token updates the person's group claims (one not signed with an accepted algorithm by the provider's keys, as Microsoft documents Entra's refreshed ID token, is left unused and the claims stay as they were; a signed one naming another person refuses); a provider that can't be reached, is throttling (429) or says it is busy (`temporarily_unavailable`, `server_error`), or refuses the broker's own request rather than the person (any error but `invalid_grant`, `interaction_required`, `login_required`, `consent_required` and `access_denied`: an expired client secret is `invalid_client`) fails that refresh only (`server_error`), and the connection stays; the log names the provider's error, and Entra's `AADSTS` codes. A check that succeeded in the last 30 seconds answers overlapping refreshes (its time is stored, so on every instance), and concurrent ones on one instance share one call. The offboarding bound is therefore the access-token lifetime plus a minute at most for OAuth-connected agents (10 minutes by default; a refresh within 30 seconds of a successful check, and the exchange of a code issued in the minute before the account was disabled, aren't checked again). Personal access tokens and web view sessions are not re-checked: an organization that needs the bound for every agent leaves `pat` off its list of agents, and approvals on the web view need a fresh sign-in at the provider anyway.

**Tools** (`src/mcp/handlers.ts`). `schemas/client/tools.json` is served exactly as written; inputs are validated with its schemas, and the tests validate every output against its `outputSchema`. A verified token becomes a `DelegateCaller`; the OAuth scope a tool needs is checked at the HTTP layer (403 `insufficient_scope`) and again in the handler. Inbound items keep the broker-verified fields apart from the counterparty's content, which comes in the untrusted wrapper with every free-text leaf sanitized by the spec 12.1.6 rules (`src/mcp/render.ts`, tested against `vectors/delivery/sanitize.json`); the text block puts it inside one `<alp_untrusted>` block with `<`, `>` and `&` escaped. `idempotency_key` returns the first result for 24 hours, to the same binding only (spec 5.4). The first call claims the key in the binding store before it sends (`BindingStore.swapIdempotency`, one atomic step), so a call with the same key while the first is still being sent sends nothing and is told so (`internal`, `retry_after` 2); a claim older than five minutes is from a call that stopped, and a later call takes it over. Every answer but `internal` stays under the key; after `internal` the message can't have arrived (nothing was sent, or the recipient's signed receipt refused it), and a call with the same key tries again. A failure once the envelope has left (its `sent` entry written; `Broker.send`'s `onSent` says when) is answered `unreachable`, since the message may have arrived: the recipient's broker answering only `internal` (still evaluating it, or failing itself), or the sender's broker failing afterwards, for example while it writes its copy. `alp_request_connection` holds the request as `pending_principal` and notifies the person; nothing is sent until they approve it on the web view, which then calls `requestConnection` as the person (spec 6.2.1). `alp_contacts` and `whoami` show the person's own outbound terms, computed with `effectiveTerms` from the org policies the server was given. `whoami`'s structured `scopes` lists every scope the agent can use, as `tools.json` describes it: what relationships allow and, while the person has another agent that can receive a message now (active, not blocked, its client allowed), what the agent may send those agents under the terms between one person's own agents (spec 6.14: the types that start a thread and those an open one takes), merged per scope, in the scopes the organization's list gives the agent's client when the list is enforced, with each type's body schema when `include_scopes` is true. It lists at most 64 (`tools.json`'s limit), sorted by id: past that, what relationships allow is kept first, so connecting another agent never pushes one out, and the scopes only the person's other agents add fill the rest in id order. Its text keeps the two apart: the scopes the agent can use with other people; the person's other agents by name (as `ranked` ranks them), how to address them, and the scopes and types it may use with them, with their body schemas when `include_scopes` is true, for platforms that show only text.

**Web view** (`src/web/app.ts`). Sign-in with the same identities, or through the organization's OpenID provider (callback `http://127.0.0.1:<WEB_PORT>/web/oidc/callback`; the session cookie is SameSite=Strict, so the callback's page continues with a same-site refresh); CSRF on every POST; a fresh sign-in for every approval, ratification, grant change, disconnection and token: the session secret again, or with OIDC a single sign-on step-up (the action waits while the person signs in at the provider with `prompt=login` and `max_age=0`; the ID token must name the same person and carry a fresh `auth_time`, and its nonce is a hash over the action and what it covers, read from the broker's state: the same terms a passkey approval signs, which for a ratification include its terms hash; the confirmed step-up waits as a single-use record for that session and action, and the person then confirms once, method `sso-stepup`; with OIDC the page's `form-action` also allows the provider's origin, which browsers check on the redirect after a form); sign-out also ends the provider's session when it offers RP-initiated logout (`client_id` and `post_logout_redirect_uri`, no ID token in the URL); every call carries the `principal_id` the page signed in as, so a page left open by an earlier holder of a reassigned address acts for no one (spec 5.2); personal access tokens are offered only when the organization's list of agents allows `pat`; CSP `default-src 'self'; frame-ancestors 'none'`; HttpOnly SameSite=Strict cookies (`__Host-` and `Secure` when served over HTTPS); 15-minute idle timeout; loopback Host names only. Disconnecting an agent revokes the delegate, its OAuth grants and its personal access tokens at once. Sessions live in the `BindingStore`, keyed by the SHA-256 of the cookie's value.

**Web view on a public origin** (`publicWeb` in `startBrokerServer`, `ALP_WEB_PUBLIC=1` in `npm start`; off by default). The router moves onto the public app and answers only to the public origin's host. Sign-in: the invite name and secret (`src/web/invites.ts`: one secret per invited person, 192 random bits, stored as a scrypt hash; invites expire and can be revoked, which ends the person's sessions), then a passkey registration before anything else (resident key, user verification required, attestation `none`; only the first registration counts, stored atomically so that of two at once only one is kept, and the page lists the person's passkeys), and on every later sign-in a passkey assertion; the session id rotates when the sign-in completes. Every action form carries `data-alp-passkey`: the page's one same-origin script (`/web/static/passkey.js`) first POSTs the form with `alp_webauthn=options` and gets a challenge of 16 random bytes followed by SHA-256 over the JCS of `{origin, principal_id, action path, terms}`, where the terms come from the broker's state and the form (spec 12.5.2); the server recomputes the hash at submission, takes the challenge once (bound to the session), requires user verification and a signature counter that moves forward, and the HumanCaller carries `webauthn-uv`, which ratification records name. Cookies `__Host-alp_web` (Secure, HttpOnly, SameSite=Strict, no Max-Age; 15 idle minutes, 12 hours in all) and `__Host-alp_device` (a year) for the notice on sign-in from a new browser (shown on the page, and sent through the Notifier when the person has a contact address). CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'`, plus COOP, CORP, Permissions-Policy and HSTS over https. Every POST checks `Origin` and `Sec-Fetch-Site` when present, and counts against a per-source limit (120 a minute, an IPv6 /64 counting as one source); failed passkey checks pause a person after 10 in 15 minutes. People sign in there by invite only: OIDC sign-in on the public web view isn't built.

**Ports.** `npm run dev`: 47110 and 47111. Client-binding tests: 47120 to 47149 (checked free, retried on a race); the OIDC tests' stand-in provider, the PGlite bridges and the hosted web-view brokers take theirs from the same pool. A test that restarts a broker on the same ports uses 47177 and 47178 instead, which no pool user takes. `ALP_TEST_PORT_BASE` moves the pool and the federation tests' ports, and `ALP_DEMO_PORT_BASE` both demos and the restart test's two ports, so set both to move `npm test` (`src/test-ports.ts`; "Ports" under Federation below).

**Limits.** Messages held for the person (no agent meets the delivery constraints, the agent `to.delegate` names can't receive them, or quiet hours) are shown on the web view, and the person can read them there, but can't release them to an agent or discard them yet (a draft held for its sender's review can be sent or discarded); the web view has no grant editor (approving a connection uses each scope's suggested fields); the MCP Events push adapter isn't built; `testing` in inbox items is always false (the core doesn't carry the sender domain's mode).

## Federation (src/federation)

Built. Everything a broker needs to federate over HTTPS, with no change to the core interfaces (one documented addition to the `DomainResolver` error contract, below).

**Endpoints** (spec 12.2.1; v0.1 has no others). Paths are `FEDERATION_PATHS` in `domain-authority.ts`:
- `POST <id>/federation/inbox`: one envelope or control envelope, `application/json`, at most 1 MiB, one strict I-JSON parse (duplicate member names, lone surrogates, a BOM and invalid UTF-8 are refused). Then the optional request-signature check, then `broker.acceptInbound`. Answers (spec 12.2.3): a plain refusal is the code's status (spec 18.3 table, `HTTP_STATUS`) with `{ error: { code, message } }`; accepted is 200 with `{ receipt }`; refused by the recipient's rules is the code's status with `{ error, receipt }` and a fixed message that names no rule; 429 and 503 carry `Retry-After`; 405 for other methods, 415 for other content types, 413 over 1 MiB. Internal errors are never echoed. A per-remote-address limit (600 a minute) answers 429.
- `GET <id>/.well-known/jwks.json`: the broker's federation keys, plus its `http` keys when it signs requests (`application/jwk-set+json`). Every key must be pinned in the domain document.
- `GET https://<domain>/.well-known/alp.json` (and the `alp.<domain>` host): `DomainAuthorityServer`, for development and the demo. In production this is a static file on the domain's own HTTPS site. It answers only for its own two host names.

**Pieces.**
- `HardenedFetcher` (`fetcher.ts`, `net-guard.ts`): every fetch a remote party can trigger. HTTPS on 443 only, a DNS name (no IP literal, no user info); resolve once and refuse unless every answer is public (loopback, RFC 1918, shared, link-local, unique-local, multicast, reserved, documentation, IPv4-mapped, NAT64 and 6to4 are refused); connect only to the checked address (pinned lookup, TLS still verifies the host name); no redirects; `getJson` takes only 200 with a JSON type; 64 KiB and 5 seconds, DNS included; `Cache-Control: no-cache`. Failures carry internal detail only. The development host map (`checkDevHostMap`: RFC 2606 names to `http://127.0.0.1:<port>`) is the only way to reach loopback; a production broker must not set it.
- `HttpsDomainResolver` (`resolver.ts`): location 1, then location 2 only after 404, 410 or no address records; never serves a document past `max_age` (at most 24 hours), even when the refresh fails; refuses a lower serial and the same serial with different content; the same-origin endpoint rule of spec 4.2.1 (`checkEndpointOrigins`, which the core's `checkDomainDocument` doesn't do); failures cached 60 seconds; discovery of never-seen domains limited to 30 a minute; every `revoked_jkt` entry seen is applied for 7 days after it was last seen; the TXT record is only a refresh hint (`StaticTxtLookup` for development, `systemTxtLookup` opt-in); JWKS cached no longer than the documents that list them; forced refreshes at most once a minute. It throws `DiscoveryError` (`discovery_failed`), with `absent: true` when the domain definitely publishes no document. `diagnostics` keeps local detail.
- `createInboxHandler` (`inbox.ts`) and `FederationServer` (`server.ts`): plain Node `(req, res)` handlers, so another server can mount them (mount the inbox before any JSON body parser). `listen` binds 127.0.0.1 by default; pass `tls` to serve HTTPS directly, or put TLS in front. For a test with real agents through a tunnel, keep federation on loopback.
- `HttpsFederationTransport` (`transport.ts`): idempotent by id (concurrent calls share the request in flight; a final receipt is reused until the envelope expires; a retry resends the identical bytes, which the recipient answers with the original receipt); never sends at or past `expires_at`; retries a network failure, 408, 425, 429, 5xx and the retryable codes with doubling backoff, ±20% jitter and `Retry-After`, inside a short budget (4 attempts, about 10 seconds), because `send` waits for the receipt. Remote error text never reaches the agent.
- Optional RFC 9421 request signatures (`http-signatures.ts`), the spec 12.2.2 profile: the transport signs `@method`, `@target-uri` (the inbox URL from the domain document), `content-type` and `content-digest` (RFC 9530, sha-256) with `created`, `expires` (300 seconds), `nonce`, `keyid` and `tag="alp-fed"`, using a separate `alp_use: http` key ring (`requestSigningKeys`). The inbox (`requestSignatures`: `verify` by default, `require`, or `ignore`; `npm start` takes `ALP_REQUEST_SIGNATURES`) verifies when present, and charges the key lookup for a never-seen sender domain to the requester's discovery budget, as `acceptInbound` does: the key must be the home broker's, pinned, not revoked, of purpose `http`; `@target-uri` is rebuilt from its own published inbox URL; the digest is recomputed; a nonce is spent once. When the signing broker isn't the sender's home broker the check is skipped and `acceptInbound` refuses the envelope anyway. A request signature never replaces an acceptance step. Covered: the derived components `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, header fields, Ed25519 signing, Ed25519 and ES256 verification, RFC 8941 dictionaries. Not covered: component parameters, `@query-param`, `@status`, responses, HMAC and RSA. Tested against RFC 9421's own B.2.6 Ed25519 vector and RFC 9530's digests.
- `brokerEntry` and `buildDomainDocument` (`domain-authority.ts`): an entry pins every published key (federation and `http`, at most 4). Org policy is private (spec 6.4), so nothing here signs or serves it; the document itself is authenticated by TLS for the domain (a signed JWKS is v0.2).
- `startHttpWorld` (`http-world.ts`): example.org's authority lists broker-a (Ana, explicit list) and broker-b (everyone else); broker-c is a rogue that claims example.org and nowhere.example; outside.example has its own authority and broker (Mallory). Each broker has its own resolver cache, transport and server; one `ManualClock` drives them.

**Ports** (fixed, checked free before listening, every server closed at the end): `npm run dev` 47110 and 47111; client-binding tests 47120 to 47149 (a pool the OIDC stand-in provider, the PGlite bridges and the hosted brokers draw from too); federation tests 47150 to 47165 (`fetcher` 47150, `resolver` 47151 and 47152, `transport` 47153 with 47154 left closed, the HTTP world 47160 to 47165); `npm run demo` 47166 to 47176; 47177 and 47178 reserved for tests that restart a broker on the same ports (`RESTART_TEST_PORTS`); `npm run demo:federation` 47180 to 47185. Another checkout running at the same time moves them (`src/test-ports.ts`): `ALP_TEST_PORT_BASE` moves the client-binding pool and the federation tests' ports together (46 ports), `ALP_DEMO_PORT_BASE` the demo (11), `demo:federation` (6, from 14 above it) and `RESTART_TEST_PORTS` (11 and 12 above it), and `PORT`/`WEB_PORT` the dev broker. Because `npm test` uses `RESTART_TEST_PORTS`, set both `ALP_TEST_PORT_BASE` and `ALP_DEMO_PORT_BASE` to move a test run.

Publish the JWKS at the `jwks_uri` and pin `broker.keys.jkts()` (next, active and retiring keys) plus any `http` keys in the domain document. `rotateKeys` prepares the next key at once, so a republished document always pins one ahead.

## Data model

| Record | Key | Notes |
|---|---|---|
| PrincipalRecord | `principal_id` (also looked up by address and by `iss`+`sub`) | The address is an alias; reassigning it to another identity retires the old principal. |
| DelegateRecord | delegate id | `client_id`, `attestation`, `class` (from the org's client rule when there is one). `created_at` is when the binding started: a label taken again after a disconnection (a token minted with that name, another client given it, the same client connecting again) starts a new binding, which reads nothing addressed to, or sent by, the earlier one; signing in again while the binding is active keeps it (spec 5.4). |
| RelationshipGrant | (principal, counterparty) | Spec grant shape; `pending` until sealed; signed by the broker (`alp-grant+jws`, local only). |
| CounterpartyRevocation | (principal, counterparty) | What the other side revoked; stops our sends. |
| ConnectionRequestRecord | (principal, id = request envelope id) | `incoming` reach the person only. |
| MessageRecord | (principal, direction, envelope id); `local_id` ULID is the inbox cursor | Holds the signed envelope, receipt and intake verification; `held` when no agent qualifies or the agent `to.delegate` names can't receive it (`held_reason`), or until quiet hours end (`held_until`). |
| DeferredNotice | id (ULID) | The person's notification of a message that arrived during the grant's quiet hours, due when they end (spec 6.7). It names the message only; `takeDueNotices` removes the due ones as it returns them, so of several instances one sends each. |
| HeldOutbound | (principal, id) | A draft held for its sender's review (spec 6.12); sent only after the person approves and a full re-evaluation. `opens_thread`: its thread id is only reserved. `delegate_since`, and between the person's own agents `to_delegate_since`: the starts of the bindings it was written by and for; it is sent only as and to those (spec 5.4). Between the person's own agents (`delivery_minimums`): `withheld` (the pointers and labels the receiving agent doesn't qualify for) and either `whole` (nothing was sent) or, when the rest went, `partial_envelope_id` (the copy it got without them); a record from before `whole` that has `withheld` is of the second kind. `state` is `pending`, then `sending` while an approval sends it (back to `pending` if the approval fails before anything was signed), and ends `sent` (`envelope_id`), `refused` (`result`: the status and code sending answered, or `undeliverable`/`internal` when the approval failed after signing; `envelope_id` only when the broker signed it), `discarded` or `expired`. |
| ThreadRecord | (principal, thread id) | State, expiry, agreed `terms_hash`, proposer, both ratification records, the single commit, and `history` (each message's transition), which the thread limit bounds. |
| RatificationRequest | id | A person's pending approval; holds the signed record once approved. |
| Ledger entries and payloads | (principal_id, seq), from 0 | Chained over digests; payloads (pointer → value maps, plus refusal detail) stored apart and erasable. |
| Receipts issued, replay keys, rate-limit hits, key rings | see `Store` | Key rings hold private keys; the file store keeps them in a separate 0600 file, the Postgres store seals them under `ALP_KEYRING_KEY` when it is set. |
| Client binding state | see `BindingStore` | oidc-provider artifacts keyed by the SHA-256 of their ids, their payloads stored without any id that is a credential (`ID_IS_SECRET`: refresh tokens, codes, registration access tokens, sessions, interactions; restored from the id on lookup), so no usable token is kept; a dynamically registered confidential client's `client_secret` is kept as issued; personal access tokens and web sessions as hashes; invites with a scrypt hash of their secret; passkeys (public key, counter); known browsers as hashes. Uses and revocations of tokens and invites write one field each, so a stale read can't undo a revocation. |

## Decisions the specification should confirm

1. **Replays** (settled by spec 10.3 and the `duplicate` vector): a duplicate of an answered envelope gets the original receipt; one first refused for a retryable reason (`rate_limited`, `thread_state`, `internal`) is evaluated again; the same id with other content is `replay`. A domain that publishes no document refuses its senders (`broker_not_authorized`) and its addresses are `unknown_recipient` at the sender; any other discovery failure is the retryable `discovery_failed`.
2. **Narrowing by omission** (settled by spec 6.6.1): a `narrowing` grant that doesn't list a scope its default covers narrows that scope away, so there is no relationship in that scope. The reference does exactly that.
3. **Forward and reverse at once** (settled by spec 6.6.1): when a default relationship's `from` and `to` both match both people (for example `@org` to `@org`), the forward and reverse terms are united, their types and their fields, so replies work in a symmetric default. The reference unites them.
4. **Plumbing types** (settled by spec 6.6): `ack`, `decline` and `error` carry only ids and enums, so they never need a grant's `may`, and either side can always acknowledge, close a thread or turn something down; `ask_human` does need it. Common-type bodies skip field coverage; notes on them don't.
5. **The ledger payload** is a pointer map (spec 11.4). The reference also keeps the reasons of a refusal (with rule ids) under the non-pointer key `detail`, for the owner's own view: the first 64, up to about 32,000 characters, and one more reason that counts the rest (`ledgerReasons`, `src/core/broker.ts`), so a draft with thousands of refused fields writes an entry of bounded size. Each reason's text is bounded too (`src/core/policy/evaluate.ts`: a pointer shown by its first 120 characters, a list of pointers by about 300, then "and N more"). Refusal entries never cross-reference another ledger.
6. **Revoked keys.** A key in `revoked_jkt` is never used (spec 4.8 rule 5); the retroactive `flagged` entries for envelopes accepted before the compromise was published are not built.
7. **Recipient-side codes.** Steps 7 and 10 report `not_accepted`, and so does step 8 when the relationship, the type or a field's coverage fails (a stranger's message too); `codeForSender` passes ten codes through: `schema_invalid`, `body_too_large`, `rate_limited`, `replay`, `expired`, `thread_state`, `unknown_scope`, `unknown_type`, `constraints_unsupported` and `internal`.
8. **`inbound_default: response_only`** only marks delivered items (`handling`), as spec 6.13 says; it refuses nothing. Messages from the person's own agents are marked the same way.
9. **`terms_hash`** is `sha256:` + base64url of SHA-256 over the JCS of `body.terms`; `commit.ratifications` holds both record hashes, sorted.
10. **Standing-grant ratification** needs a grant (not a default alone) with `commit: within_limits`, a scope that defines a limits check (only `alp.meeting/1` today), and no `ratification.required_scopes` entry.
11. **Domain document `mode: testing`** is carried but not yet surfaced (`testing` in inbox items is always false).
12. **Attestation order** follows the spec: self < vendor < native < org-client < tenant. The sign-in page refuses a client the organization lists as `org-client` if it doesn't authenticate at the token endpoint (a public client can't stand for a credential the broker issued).
13. **One person's own agents** (spec 6.14): a delegate may write to another delegate of the same principal (`to` = its own address, `to_delegate` named). The effective terms are `self` (every type but negotiation, every field). Delivery minimums apply per field to that one delegate at the sender's side, with `otherwise: hold` (deliver the rest; hold the full message for the person) or `block` (refuse with `org_policy`), so the envelope carries no `constraints`. The thread record is the person's own, so each message is applied to it twice (as received, then as sent); terminal states make the second application a no-op. Sender-added `labels` are message-wide, so they withhold every field.
14. **A `to.delegate` naming no agent that can receive the message** (spec 6.7): the recipient's broker accepts the envelope, with the receipt any accepted message gets, and holds it for the person's web view, with a notification that leaves out the label the sender chose. It never falls back to the person's other agents: the sender addressed one. The agent named counts only if its binding had started when the message was received. Before it answers, the broker does the same work, store writes included, whether the message is delivered, held for this reason or held because no agent meets its constraints (`broker.test.ts` counts them): the hold itself is recorded in the `received` entry written either way (`ref`; the entry's random salt keeps the receipt's `ledger_hash` from revealing it), so a broker that stops right after answering loses only the notice; what a hold adds (the rate-limit record of the notification, the notification) and the pushes to agents are handed, after everything awaited, to `BrokerOptions.background`, which by default runs them on the next turn of the event loop, after the federation inbox has written its answer. Between two principals of one broker, the recipient's side runs inside the sender's own call, so that work waits until the sender's whole call has returned (`AsyncLocalStorage`): the broker's own entry points run in `Broker.asOneAnswer`, and so does each client-binding tool call (`runTool`), its idempotency record included. With a database store, it can still overlap the requests that come next. Notifications for messages held because of the person's agents (this reason, or constraints none meets: the sender controls both) are limited to one an hour per sender, as spec 6.7 allows; the page lists them all. Outside the grant's quiet hours an `ask_human` is notified each time as an `ask_human`, whatever it waits for; during them the person is told of nothing from that sender until they end, whatever the message waits for (`afterAccepting`): notifying only of messages held because of the person's agents would let the sender disturb the person and learn from their response that a message waits for them. The notification such a message would have brought is kept (`DeferredNotice`, written after the answer like the rest) and sent once the quiet hours end by `sendDueNotices`, which the servers run every minute (`startNoticeTimer`): it decides then what the person is told, as for a message arriving at that moment (each `ask_human`; the hourly limit for messages held because of the person's agents; nothing for a message an agent can now read, and nothing for a later holder of the address). A notice sent when the quiet hours end tells the sender no more than a notice of a message sent then. A broker that stops after taking a due notice and before sending it loses that notice, as one that stops right after answering does. A process that stops (`stopBroker`, on SIGINT and SIGTERM) closes its listeners, waits up to 10 seconds for that work (`Broker.settled`), then closes its stores. Between one person's own agents the sender's broker checks the name first (`unknown_recipient`), so this applies there only to an agent that is blocked or whose client the list refuses.
15. **A label used again is a new binding** (spec 5.4): `registerDelegate` keeps a binding's start (`DelegateRecord.created_at`) only for the same client signing in again for the same person while the binding is active; anything else starts a new one. The visibility rule (`agentMayRead`) hides a received message addressed to the reader's delegate id that its broker received (`stored_at`) before the binding started, and a message sent from that delegate id that its broker signed (`envelope.created_at`) before then: a sent message's record is stored only once the receipt is back, which may be after a new binding started. The stores apply the same cut in the inbox query (`MessageQuery.bindingSince`), so an earlier binding's backlog costs a new one nothing, and a page that read only records the reader may not see says there is more, with a cursor past them. Acknowledgements are per binding: one made before the binding started doesn't count (`ackedBy`). `alp_send`'s idempotency keys and held messages are per binding too: a held message records the bindings it was written by and for, and `heldBindingChanged` decides whether it can still be sent; if not, the web view offers only to discard it. So are the client binding's credentials: a personal access token records its binding (`PatRecord.binding`), and a connection (an oidc-provider grant) the binding it was authorized for (`AuthServer.bindGrant`, carried in each access token as `alp_binding`), so neither acts for a later agent given the name, even when the earlier one was disconnected some other way than the web view (`Broker.revokeDelegate` leaves grants in place) and the same client connected again; such a connection can't refresh either. A connection authorized before bindings were recorded acts for the client's newest active agent, as it did, until it next gets a token, which binds it to that agent (`extraTokenClaims`) if the agent's binding had started when the connection was authorized (the grant's `iat`, in whole seconds); otherwise `findAccount` refuses the token and revokes the connection. Messages to the person stay readable, as for any new agent. Timestamps have millisecond resolution, so a message stored in the same millisecond as a new binding started counts as the new binding's; in practice a disconnection and a new sign-in come between the two. A held message records the binding's start exactly and compares it for equality, so it never goes to a later binding. Records written before this rule kept the first `created_at` across a re-connection.
16. **Reading a conversation** (spec 9.2, 12.1.3, 12.1.4): a thread takes at most 200 messages besides one that ends it, so `Broker.thread` reads all of a thread's records, newest first (`MessageQuery.order` `desc` with a `before` cursor), at most about four times the limit (one person's own agents' copy keeps two records of each message), and returns those the agent may read. `alp_thread` shows the latest `limit` of them (default 50) with `earlier` and a `before` cursor, and computes `next_types` and `counterparty.agents` from all of them, whatever the page. In a thread that holds 200 messages, `next_types` keeps only what ends it (a `decline`, or an `ack` outside `agreed`), and the text says so and to continue in a new thread. A reply that names no `to_delegate` goes to the agent that sent the message it answers, or for a reply to one of the sender's own side's messages, to the agent that message was addressed to (`replyAddressee`, in the client binding); a follow-up goes where `to_delegate` says.
17. **More to remove than `decision.redacted` can list** (spec 6.6 S4 and S5, 8.2): with redaction `redact`, or an organization's `redact` rule, the removed leaves are listed in `decision.redacted`, which takes at most 64 pointers of at most 512 characters (`common.schema.json`). When a draft has more to remove, or a removed leaf's pointer is longer, the evaluator refuses it as without redaction (`not_disclosed`, or `org_policy` naming the rule), before anything is signed: an envelope listing them wouldn't be valid, and every broker refuses it (`bad_envelope`). The refusal's reasons go to the ledger bounded (`ledgerReasons`). Before, such a draft was signed, sent and refused, and its `sent` entry listed every removed pointer (105 MB for a 30,000-character member name above 3,500 fields, which took about 18 seconds). The specification could say this outright.

## Not built yet (and where it goes)

- **OIDC sign-in, the remaining parts**: tests against Entra of what the test against a live tenant didn't try, such as Conditional Access, group claims and guests ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)); certificate credentials (`private_key_jwt`) for the broker's own client at the provider; fetching an overflowed group list from Microsoft Graph (the sign-in is refused instead); front-channel and back-channel logout from the provider; a provider on a private network; the re-check for personal access tokens and web view sessions; OIDC sign-in on the web view served on a public origin.
- **SCIM provisioning** (spec 5.8): offboarding relies on the re-check at refresh.
- **Hosted, per instance:** the federation inbox's per-address limit and request-signature nonces live in each instance's memory, not in `windows`; no overall cap on connector sign-ins started or sign-in page requests from many addresses (the platform's rate limits are that layer); when two first sign-ins of one person land on two instances at once, migration 006 makes the second fail rather than retry; dynamically registered clients' secrets aren't hashed.
- **The web view behind an organization's SSO anywhere but loopback.** With OIDC sign-in, approvals on the loopback view take a single sign-on step-up at the provider; on a public origin the view runs behind invites and passkeys; by default it is loopback-only with a session-secret re-check. Where it goes: start from the refusals in `startBrokerServer` (`src/server.ts`) and `npm start` (`src/main.ts`). The web view is `src/web/app.ts`: its public-origin mode already has the HTTPS protections (`__Host-` cookies, Origin and `Sec-Fetch-Site` checks, the strict CSP), and its loopback mode the OIDC sign-in and the step-up (`src/oauth/oidc-signin.ts`); the web view's OIDC callback is fixed at `http://127.0.0.1:<WEB_PORT>/web/oidc/callback` today. The result must meet spec 12.5.2: sign-in through the organization's provider, a step-up whose challenge covers the hash of the terms, POST-only actions with CSRF tokens, the CSP and `__Host-` cookies.
- **An outside DLP service.** The `Broker` takes any `DlpHook` (`src/core/policy/dlp.ts`), but `npm start` passes none, so the sample check runs, and it refuses a policy whose `dlp.hook` names a service. Adapters (Microsoft Purview processContent, Google Sensitive Data Protection, ICAP) are deployment choices outside the spec.
- **Notification delivery.** `ConsoleOutboxNotifier` (`src/web/notifier.ts`) prints each notification and appends it to `outbox.jsonl`; nothing sends email, SMS or Teams messages yet.
- **For a hosted deployment** (`deploy/VERCEL-SUPABASE.md`): a Vercel entry point (`startBrokerServer` builds and listens in one step; a function would also need a scheduled call of `sendDueNotices`, which the server's minute timer makes), an email notifier, replacing a lost passkey, rotating `ALP_KEYRING_KEY`, and a run against a real Supabase project (the Postgres code runs on PGlite in `npm test`; the whole suite passed against a PostgreSQL 17.10 server with `ALP_TEST_POSTGRES_URL` on November 8, 2026, and `.github/workflows/ci.yml` runs it on Postgres 17; not yet on Supabase). Web sign-ins and passkey checks go to the operator's log, not the OCSF security-event stream, whose event list (a closed enum in the spec's schema) has no name for them yet.
- **Push adapters** (MCP Events, routine webhooks, mail to the agent). Agents poll; `bridge-kit/poller/alp-watch.mjs` is an example script that polls the REST inbox and starts an agent that a command starts (not a hosted agent product such as Claude or Muse, whose documentation describes no push for custom connectors) only when something new has arrived.
- **Machine-readable refusal details:** what is wrong with each field is in `message` only (`toSchemaErrors`, `src/core/ajv.ts`; the per-reason text in `src/core/policy/evaluate.ts`); distinct authentication codes in REST error bodies and a structured `details` array would change the closed error schema in `tools.json` and `openapi.json` (spec 12.1, 18.3).
- **A person's own agents in structured results:** the person's other agents are listed only in `alp_whoami`'s MCP text and in an own-agent `unknown_recipient` refusal's message (a structured result names one only as a message's sender, in a message's signed envelope with `include_envelope`, its `from` and `to`, or in `alp_thread`'s `counterparty.agents` as an agent that wrote in that thread); `alp_whoami`'s `scopes` merges what the agent may send them with what relationships allow, without saying which types work with whom; inbox items don't say that another of the person's agents already replied. These are output-schema changes.
- **A polling credential for OAuth-connected agents:** the web view refuses a personal access token named after an agent connected through OAuth, so a poller with its own name doesn't see messages addressed to that agent with `to_delegate`; a content-free watch credential, and per-agent read limits on `alp_inbox`, need a new credential type.
- **Stricter message rules:** one date-time spelling, semantic checks on time windows (end after start, duration within the window), `schema_invalid` at S1 for fields a scope doesn't define (today `not_disclosed` at S5), and example bodies inside scope definitions (in v0.1 they are in the OpenAPI document). Each changes which messages are accepted, so it needs spec text and vectors.
- **Retention:** `retention.ledger_days` is recorded but nothing is purged (`npm start` warns); a daily purge that keeps the hash chain intact and in-process rotation of the JSONL files aren't built.
- **Operator commands:** rotating the broker's signing keys (`Broker.rotateKeys` exists, but nothing calls it), re-sealing under a new `ALP_KEYRING_KEY`, revoking every connection of one person or one client, and listing connections, each with `admin_action` events. A policy kill switch and `SIGHUP` stop a person or a client today. When the identity provider refuses a person at a refresh, only that connection ends; their personal access tokens and web sessions aren't revoked with it.
- **Further limits:** the limit between a person's own agents is set by `ALP_OWN_AGENT_RATE_LIMIT` or the `Broker` limits only, with no policy field; per-agent shares of a person's limits with counterparties, a per-token request budget on `/mcp` and `/rest`, and folding repeated identical refusals into one ledger entry aren't built.
- **Client metadata documents:** each connected client's last good document isn't kept, so a refresh after oidc-provider's cache has dropped it needs a live fetch (listed clients are fetched outside the budgets); unlisted documents are fetched before they are refused in `enforce` mode, and dynamic registrations aren't refused there.
- **Operations:** JSON logs with request ids, metrics, container base images pinned by digest, and a runtime image without npm and the demo and test kits.
- **The signed ledger export** (spec 11.7): each person downloads their ledger from the web view as plain JSON (`/web/ledger.json`); the signed export format, an organization-wide ledger feed and separately encrypted payloads aren't built.
- **The store-and-forward retry schedule** (30 seconds doubling to 1 hour until `expires_at`): the transport retries inline for about 10 seconds because `send` waits for the receipt; a persistent outbox would also retry failed control messages. Without one, a send that wasn't delivered shows only in its `alp_send` answer: `alp_thread` lists delivered messages only (each with `status` `delivered`), where spec 10.2 has the delegate see the outcome there.
- The resolver keeps the highest serial and the remembered `revoked_jkt` entries in memory only; a restart forgets them (they belong in the store).
- The pause after three ratification declines in 24 hours, legal hold (spec, v0.2), timed purging for `retention_max` (the broker refuses a limit it can't keep), and the retroactive `flagged` ledger entries.

[KNOWN-GAPS.md](../KNOWN-GAPS.md) lists the gaps of v0.1 and of this broker that implementers and operators most need to plan around.

## Dependencies (exact pins)

| Package | Version | Why |
|---|---|---|
| `jose` | 6.2.13 | JWS (Ed25519, the RFC 9864 `Ed25519` alg), thumbprints, and the ID token checks of OIDC sign-in. One copy, shared with the MCP SDK and oidc-provider. |
| `ajv`, `ajv-formats` | 8.20.0, 3.0.1 | JSON Schema 2020-12 for the spec's schemas. |
| `ulid` | 3.0.2 | Monotonic ULIDs. |
| `@modelcontextprotocol/server`, `@modelcontextprotocol/express` | 2.4.0, 2.0.2 | MCP 2026-07-28 server and its Express adapter. |
| `oidc-provider` | 9.13.3 | The authorization server (MIT; supports client ID metadata documents). The OIDC tests also run it as the stand-in identity provider. |
| `express`, `cors` | 5.3.0, 2.8.6 | HTTP for the bindings and the web view. |
| `zod` | 4.6.7 | MCP tool schemas (the SDKs' peer). |
| `postgres` | 3.4.9 | The hosted store (Supabase: transaction pooler with `prepare: false`). |
| `@simplewebauthn/server` | 14.0.3 | Passkeys on the public web view (MIT; its dependencies are MIT, BSD-3-Clause, Apache-2.0 and 0BSD). |
| dev: `@modelcontextprotocol/client`, `@modelcontextprotocol/sdk` | 2.4.0, 1.32.2 | Scripted clients for the tests, the demo and the preflight (2026-07-28 and 2025-11-25); not in the Docker image. |
| dev: `@electric-sql/pglite` | 0.5.11 | Postgres in the test process (Apache-2.0), so the Postgres suites need no server; the bridge is `src/storage/pglite-bridge.ts` (no `@electric-sql/pglite-socket`, whose extension peers aren't optional). |
| dev: `typescript`, `@types/node`, `@types/express`, `@types/cors`, `@types/oidc-provider` | 6.0.3, 22.20.5, 5.0.6, 2.8.19, 9.13.1 | Type checking only. |

No RFC 8785 library: `src/core/jcs.ts` is about 80 lines and passes the RFC's own vectors. No RFC 9421 library: the spec makes request signatures a MAY, so `http-message-signatures` was dropped; `src/federation/http-signatures.ts` implements only the optional profile's subset (spec 12.2.2) and passes RFC 9421's own Ed25519 vector (B.2.6) and RFC 9530's digest examples. `.npmrc` sets `save-exact`; `npm ci` runs npm's audit (0 vulnerabilities on November 7, 2026).

## The protocol's name in code

Runtime strings come from `src/core/protocol.ts` (`PROTOCOL`: "Agent Liaison Protocol", the short id `alp`, the version member `alp`, the `alp:` address scheme, the `alp.` scope prefix, the `alp-` typ prefix, `alp.json`, the `alp.<domain>` host, `_alp` with `v=ALP1`, the `alp_` tool prefix); schema ids are read from each schema's own `$id`. Test data uses the same literals (addresses such as `alp:ana@example.org`, scopes such as `alp.briefing/1`), and the signed vectors are regenerated by `tools/spec` (`npm run vectors && npm run examples && npm run check`) after any change to them. No file or directory in `reference/` carries the name.
