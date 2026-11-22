# Implementing ALP

This guide is for anyone building a broker or a client of the Agent Liaison Protocol (ALP) v0.1 from [the specification](spec/alp-v0.1.md). It adds no requirement of its own. It suggests an order for reading the specification, names the schemas, vectors and requirements that go with each part, and says what each of the three ways of checking in this repository tells you. Where this guide and the specification differ, the specification governs.

## Before you start

- Version 0.1 is a draft for implementers, and v0.x releases can change incompatibly (specification, "Status of this document" and Section 16).
- Every section carries a maturity label. **Core** sections are stable enough to implement now. **Experimental** sections are specified and testable but more likely to change: federation between brokers, push adapters, the Native Client (a vendor's built-in client) and the Provider Broker (a provider's broker for its own consumer domain). **Future** sections are not normative.
- Section 1.7 is the reading guide: broker implementers read Sections 4 to 12 and the class they target in Section 13; people building agents in client mode read Sections 12.1 and 13.8; security reviewers start with Sections 1.4, 14 and 15.
- Anyone can implement ALP from the specification, schemas and vectors without asking, including in a broker they sell. Code copied or adapted from `reference/` stays under the reference broker's license, FSL-1.1-ALv2, until the version it came from becomes Apache-2.0 ([README](README.md#license)).

## Which class you are building

An implementation claims one or more conformance classes, names the protocol version, and passes the vectors that apply to it (Section 13.1). There is no certification program in v0.1. Requirement ids such as `BC-15` are stable within a version, so a test report can cite them.

| Class (Section 13.2) | Who | Builds on | Requirements |
|---|---|---|---|
| Broker Core (BC) | Every broker | | BC-1 to BC-25 (13.3) |
| Organization Broker (OB) | An organization's own broker, Local by default | BC | OB-1 to OB-6 (13.4) |
| Hosted Broker (HB) | A third party's broker for others | BC | HB-1 to HB-5 (13.5) |
| Provider Broker (PB-Core), Experimental | A provider's broker for its own consumer domain | Parts of BC | PB-1 to PB-8 (13.7) |
| Native Client (NC), Experimental | A vendor's built-in client | | NC-1 to NC-5 (13.6) |
| Client-mode Delegate (CD) | An agent configured with the client binding | | CD-1 to CD-6 (13.8) |

A Client-mode Delegate's requirements apply to how an agent is configured and instructed; a person or administrator meets them through the vendor's settings and the instruction snippet (Sections 12.1.8 and 13.8). [CONFORMANCE.md](CONFORMANCE.md) lists every requirement with the sections it points to, the vector files that exercise it, and what the broker checker can see of it.

### What the Local profile lets you leave out at first

In the Local profile, one organization's broker serves its own people, whichever vendor each person's agent comes from. It needs no domain document, no published policy and no federation listener (Section 3.3), and requirement OB-1 is to run that way. Envelopes are still signed, for ledger integrity, and acceptance steps 0 to 6 (the checks a receiving broker runs on each envelope, in order; Section 12.2.4) are met from local state: the broker verifies its own signature with its own keys, the audience is itself, and it is home for both principals (Section 12.2.4). Its principals can exchange envelopes only with principals of the same broker (Section 4.5).

A Local broker needs none of Sections 4.2 to 4.8 (Section 4). So an Organization Broker can start with addresses (Section 4.1) and home-broker resolution from its own configuration (the last paragraph of Section 4.5), build steps 2 to 7 below, and leave the domain document, the published key set and pinning for step 8. In step 2 it needs keys, canonical JSON and detached signatures to sign and verify its own envelopes, but not the published key set or the pinning rules of Section 4.8. OB-6 applies once it federates. Note that whenever the sender's or the recipient's domain publishes a document, acceptance steps 3 and 6 apply to a broker's own principals too (Section 12.2.4).

## An order of work

Each step names the sections to read, the schemas in `schemas/`, the vector files in `vectors/` your code should pass, and the Section 13 requirements whose sections it covers. Together with the Local profile above (OB-1), the steps place every requirement of Section 13. The schema and vector lists come from Appendix B of the specification and [vectors/README.md](vectors/README.md).

### 1. Addresses and the domain document

- **Read:** Sections 4.1 to 4.5 and 4.7 (a Local broker needs only Section 4.1 and the last paragraph of Section 4.5 for now). Section 4.3's fetcher rules apply to every URL that inbound data names.
- **Schemas:** `domain-document.schema.json`, `common.schema.json`.
- **Vectors:** `domain/resolution.json`: document validity, including the rules a schema can't express (one `"*"` broker, no overlapping lists, same-origin endpoints, addresses on the document's domain), home-broker resolution and TXT record parsing.
- **Requirements:** BC-1, BC-24; when you publish a document, OB-6, HB-1, HB-5 and PB-1.

### 2. Keys, canonical JSON and detached signatures

- **Read:** Sections 4.8, 8.1, 8.3 to 8.5, 8.7 and 8.8. A broker publishes its public keys as a JSON Web Key Set (JWKS) at `jwks_uri`, and a domain pins a broker's federation keys by listing their RFC 7638 thumbprints in the broker's `jkt` (Section 4.8); the published key set and pinning wait for step 8 at a Local broker.
- **Schemas:** `jwks.schema.json`.
- **Vectors:** `jcs/jcs.json` (canonicalization; its `expected_error` cases, duplicate member names, must be refused), `signatures/detached-jws.json` (exact Ed25519 values, since Ed25519 is deterministic; ES256 cases are verify-only) and `signatures/jkt.json` (RFC 7638 thumbprints of the test keys).
- **Requirements:** BC-15.

### 3. Envelopes and the scope schemas

- **Read:** Section 7 (scopes, body schema rules and the five core scopes; Section 7.8 is the minimum a Provider Broker installs) and Sections 8.2, 8.6, 8.9 and 8.10.
- **Schemas:** `envelope.schema.json`, `control.schema.json`, `messages/*.schema.json`, `scope-definition.schema.json` and `scopes/*.json`.
- **Vectors:** `envelope/validity.json` (validity against the schema plus the lifetime rules, and the code a receiving broker returns; its `raw_text` cases must be parsed from the text) and `scopes/bodies.json`.
- **Requirements:** BC-14, BC-15; PB-3.

### 4. Grants, organization policy and the two evaluation algorithms

- **Read:** all of Section 6. The two algorithms are sender-side evaluation (6.6) and recipient-side evaluation (6.7).
- **Schemas:** `grant.schema.json`, `org-policy.schema.json`.
- **Vectors:** `policy/sender.json` (Section 6.6) and `policy/recipient.json` (steps 7 to 11 of Section 6.7, for envelopes that already passed steps 0 to 6). Both use the organization policy of `example.org` in `world.json`.
- **Requirements:** BC-8 to BC-13, BC-22, BC-23; OB-3; HB-3; PB-4.

### 5. Threads and ratification

- **Read:** Section 9, and Section 7.7 on negotiable scopes.
- **Schemas:** `ratification.schema.json`.
- **Vectors:** `threads/conversations.json` (replies, follow-ups, the types each state accepts, the thread limit and how threads end) and `threads/meeting-commit.json` (an `alp.meeting/1` negotiation, both ratification records and the commit).
- **Requirements:** BC-16, BC-17.

### 6. Delivery, receipts and ledgers

- **Read:** Sections 10 and 11, including retention, erasure and organization records (Section 11.6).
- **Schemas:** `receipt.schema.json`, `ledger-entry.schema.json`, `ledger-export.schema.json`, `security-event.schema.json`.
- **Vectors:** `ledger/matching-ledgers.json` (two principals' ledgers for one envelope, with the cross-references through the receipt), and the replay and duplicate cases of `federation/acceptance.json`.
- **Requirements:** BC-18, BC-19, BC-20; OB-5; PB-6.

### 7. The client binding

- **Read:** Section 5 (principals, delegates, what a delegate can never do, the OAuth profile, personal access tokens, revocation), Section 12.1 and Section 12.5 (the web view, and notifications that only notify). A Native Client also reads Section 4.6, which says how it finds a person's home broker and then the authorization server through the endpoint's protected resource metadata (the OAuth metadata, RFC 9728, that tells a client where to sign in).
- **Schemas:** `client/tools.json`, the fixed tool list, which a broker serves exactly as written (Section 12.1.2), and `client/openapi.json`, the REST mirror a broker SHOULD offer (Section 12.1.9).
- **Vectors:** `delivery/visibility.json` (what one agent may read) and `delivery/sanitize.json` (sanitizing free text on delivery, including prompt-injection cases).
- **Requirements:** BC-2 to BC-7, BC-21; OB-2, OB-4; PB-8; for clients, NC-1 to NC-5 and CD-1 to CD-6.

### 8. Federation

- **Read:** Section 12.2 (Experimental): the endpoints, optional request signatures, responses and acceptance steps 0 to 6. Read Sections 4.3 to 4.8 again as the receiving broker.
- **Vectors:** `federation/acceptance.json` (steps 0 to 6 for each raw request body, given the domain documents fetched, the highest serial seen and the replay window) and `federation/connection-requests.json` (the uniform answer to a connection request).
- **Requirements:** OB-6, HB-5, PB-2, PB-5; BC-22 across brokers. BC-25 asks for every vector in `vectors/` except where a class exempts it.

### 9. The operator statement (Hosted and Provider Brokers)

- **Read:** Section 13.9. A Hosted Broker and a Provider Broker publish an operator statement, linked from `operator_statement` in their domain-document entry, kept current and dated: how principals are verified, data use and retention, jurisdictions, subprocessors, key custody, an abuse contact and how data is exported. A Hosted Broker also isolates its tenants (HB-2), and a Provider Broker lists a security contact in its domain document (Section 4.2).
- **Vectors:** none.
- **Requirements:** HB-2, HB-4; PB-7.

## Checking your work

Three things in this repository check different parts of your work, and each answers a different question.

### The vectors: your own logic

Run the vectors through your implementation's own code paths: parse, canonicalize, verify, evaluate ([vectors/README.md](vectors/README.md)). The other files refer to the shared fixture [`vectors/world.json`](vectors/world.json): its clock (`now`, `2026-11-09T14:00:00Z` unless a case gives its own; `clock_skew_seconds` 300), the fictional brokers, principals, domain documents, key sets, the organization policy of `example.org`, and the recipients' delegate bindings. The README also gives the conventions for pointers, hashes and ids. Every key in `vectors/keys/` is TEST-ONLY: never use one, or anything derived from it, outside tests.

What it tells you: whether your code reproduces the outcome each case expects. What it does not: anything no case covers. Some requirements have no vector at all, among them the OAuth profile (BC-5), the security event stream (BC-20), the web view (BC-21) and the hardened fetcher (BC-24); CONFORMANCE.md says "none" for each. A failing vector is a bug in the implementation or in the vector; where the specification's text and a vector disagree, the vector is the bug unless an erratum says otherwise (specification, "Status of this document"). Please report either.

The reference broker runs every vector in its own test suite (`cd reference && npm test`); its code is under FSL-1.1-ALv2.

### An evaluator written independently of the reference broker: the vectors themselves

[`tools/spec`](tools/spec/README.md) holds the steward's generator and an evaluator written independently of the reference broker, by the same project:

```sh
cd tools/spec && npm ci && npm run check
```

It compiles every schema, checks the scope body-schema rules, the tool list and the OpenAPI mirror, recomputes the canonical forms, signatures and thumbprints, and runs its own implementation of acceptance steps 0 to 6, both evaluation algorithms, home-broker resolution, the thread rules, the ledger chain and the sanitizer against every vector.

What it tells you: that the schemas compile and that an evaluator written apart from the reference broker agrees with every expected outcome in the vectors. What it does not: it never runs your code. Run it when you suspect a vector, or propose a new one ([CONTRIBUTING.md](CONTRIBUTING.md)).

### The broker checker: a running broker

[`tools/check`](tools/check/README.md) (`alp-check`) is pointed at a running broker. It needs no credentials and reports what it can observe from outside:

```sh
cd tools/check && npm ci
node check.mjs example.org                     # a domain that federates: everything is found from its document
node check.mjs --broker https://broker.example.org \
  --mcp https://broker.example.org/mcp --rest https://broker.example.org/rest
                                               # a Local-profile broker, which publishes no domain document
```

In these commands, `example.org` stands for your own domain and `broker.example.org` for your own broker. It checks the domain document and its semantic rules, the brokers' key sets and pinning, the DNS TXT record, the sign-in metadata (protected resource metadata and the authorization server's metadata), the `401` challenge to a request with no token, and how the federation inbox (the URL where other brokers post envelopes, Section 12.2) refuses envelopes that fail acceptance step 0, or step 1 because the sender's domain cannot exist. Every check quotes the sentence of the specification it enforces and says whether it is required or recommended. The inbox probes are addressed to an address nobody holds; `--no-inbox-probes` sends nothing to the inbox. A domain's document can name brokers that someone else runs for it, and each of them receives the checker's requests. Run it against domains and brokers you operate, or are allowed to test: the target's operator may see its requests in their logs.

What it tells you: whether the parts of your broker that anyone can reach behave as the quoted sentences say. What it does not: anything that needs a token, anything that needs the checker to act as a peer broker with its own domain and keys (signatures, receipts, replay), and anything not observable from outside, such as ledgers, grants, ratification and kill switches. A report with no failures does not mean an implementation conforms. A report also counts the required checks it could not decide (after a rate limit or a server error, for example) and then exits with code 4: it says nothing about those checks, so run it again later. CONFORMANCE.md shows, for each requirement, which checks observe part of it. CI runs the checker against the reference broker with federation on, on one machine through a development host map ([tools/check/ci/run-against-reference.sh](tools/check/ci/run-against-reference.sh)): this shows that the checks' expectations hold for the reference broker, and nothing about any other implementation; it exercises no TLS and no DNS.

## Reporting what you found

- **An implementation report** is the most useful contribution. Open an issue with the "Implementation report" template: what you built, which classes and sections, what did not work or was unclear, your vector and checker results, and a link if there is one. Cite requirement ids where you can.
- **Problems with the specification** go in an issue with the "Specification feedback" template. Open an issue first for anything normative, and describe the problem before the solution ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **Questions** can go in an issue, or to hello@agentliaisonprotocol.org.
- **Security problems** go privately to security@agentliaisonprotocol.org, never to a public issue ([SECURITY.md](SECURITY.md)).

Before reporting a difference from the reference broker, read [KNOWN-GAPS.md](KNOWN-GAPS.md), which lists the known gaps of v0.1, the reference broker's gaps and where it differs from the specification. Then read the decisions in [reference/ARCHITECTURE.md](reference/ARCHITECTURE.md#decisions-the-specification-should-confirm) that the specification should confirm.
