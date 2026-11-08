# Conformance vectors

These vectors exercise the Agent Liaison Protocol (ALP) v0.1 specification ([spec/alp-v0.1.md](../spec/alp-v0.1.md)). They are licensed under Apache-2.0.

**Every key in `keys/` is TEST-ONLY.** The private keys are published on purpose so that anyone can reproduce the signatures. Never use them, or anything derived from them, outside tests.

## Shared fixture

[`world.json`](world.json) is the fixture the other files refer to:

- `now`: the clock for every vector (`2026-11-09T14:00:00Z`) unless a case gives its own `now`; `clock_skew_seconds` is 300;
- `brokers`: the fictional brokers (`https://broker.example.org`, `https://broker.partner.example`, `https://rogue.example`, `https://hosted.example.net`, `https://old-broker.example.org`, `https://broker.outside.example`);
- `principals`: Ana and Lee (`example.org`), Pat (`partner.example`), Mallory (`outside.example`) and others, with their `principal_id`s and delegates;
- `domain_documents`: keyed `<domain>@<serial>`; `example.org@41` is an older document that named a broker since removed;
- `jwks`: each broker's published JWKS, keyed by `jwks_uri`. `broker.partner.example` also publishes a key its domain does not pin;
- `org_policies`: the private organization policy of `example.org` (groups, classification rules `fin-1`, `conf-1` and `restricted-1`, the `analysts-leaders` default relationship, DLP, the `clients` allow-list, delivery minimums and kill switches);
- `delegates`: the recipients' delegate bindings (attestation, class, `no_training`, retention), used for `to.delegate` and delivery constraints. Lee has four: `agent-b`; `agent-e`, a consumer client the `clients` list names; `agent-a`, which a kill switch blocks; and `old-tool`, whose client the list doesn't name (so, in `enforce` mode, it can't receive anything).

## Files

| File | What a conforming implementation must reproduce |
|---|---|
| `jcs/jcs.json` | Each `input_text`, parsed strictly and canonicalized with JCS, equals `expected`; `expected_error` cases must be refused (duplicate member names). |
| `signatures/detached-jws.json` | For Ed25519 cases: the JCS form, the protected header and the exact `broker_sig` (Ed25519 is deterministic), and the envelope hash. ES256 cases are verify-only. |
| `signatures/jkt.json` | RFC 7638 thumbprints of the test keys. |
| `envelope/validity.json` | `expected.valid` against the envelope or control schema plus the semantic rules (lifetime at most 7 days, `expires_at` after `created_at`), and the federation code a receiving broker returns. `raw_text` cases must be parsed from the text (duplicate member names). |
| `scopes/bodies.json` | Each body is valid or invalid against the core scope's schema for its type. |
| `domain/resolution.json` | Domain document validity, including the semantic rules (one `"*"` broker, no overlapping lists, same-origin endpoints, addresses on the document's domain); home-broker resolution; TXT record parsing. |
| `policy/sender.json` | The sender-side evaluation (spec 6.6) for each `caller`, `draft` and set of explicit `grants`, under `world.org_policies["example.org"]`: `outcome` (`allowed`, `redacted` or `rejected`), and either the `code`, `pointers`, `rule` and `categories` of a rejection, or the `grant`, `labels`, `redacted`, `body` (after redaction), `policy_ids`, `constraints` and `status` of an allowed message. |
| `policy/recipient.json` | Recipient-side steps 7 to 11 (spec 6.7) for envelopes that already passed steps 0 to 6: `outcome` (`accepted` or `refused`), `code`, `contact_attempt`, and `delivery` (`deliver`, `hold_for_web_view`, or `hold_until` with `hold_until`). An agent counts as able to receive only if no kill switch blocks it and the `clients` list allows its client; with `to.delegate`, only the agent it names counts, and when it can't receive the message (or doesn't meet its constraints) the envelope is accepted and held for the person, never refused and never given to the person's other agents. `state.recent` is the number of messages already accepted in the rate-limit window. |
| `federation/acceptance.json` | Acceptance steps 0 to 6 (spec 12.2.4) for each raw `request_body`, given the receiving broker, the domains it serves, the domain documents fetched (`context.domain_documents` names keys of `world.domain_documents`; a missing domain has no document), the highest serial seen per domain and the replay window: `result` (`authenticated`, `duplicate` or `refused`), and for refusals the `code` and `step`. |
| `federation/connection-requests.json` | The answer to a connection request that passed steps 0 to 6 (spec 6.2.2): `status` `accepted` with no `ledger_hash` whether or not the address exists, or the same `unknown_scope` refusal for a request naming no known scope. |
| `delivery/visibility.json` | What one agent may read (spec 5.4, 6.11, 12.1.4), the same rule for `alp_inbox`, `alp_thread` and `alp_ack`: `expected.visible` lists the ids of `messages` the `reader` may see. A reader's `since` is when its binding started; a received message addressed to it counts only if its `stored_at` (when its broker received it) isn't earlier, and a message it sent only if its `created_at` (when its broker signed it) isn't earlier. |
| `threads/meeting-commit.json` | A `alp.meeting/1` negotiation: reply hashes, `terms_hash`, both ratification records and the commit that references them. |
| `threads/conversations.json` | Threads as conversations (spec 7.8, 9.2 to 9.4), each case one broker's copy of a thread (Ana's: her turns go out, Lee's come in): for each turn, whether the thread rules accept it and the thread's state after it. Covers replies (naming an earlier turn, from either side, of a type the scope's `replies` map allows; an `accept` or `counter` only of the other side's latest proposal), follow-ups (naming none), the types each state accepts (in a negotiable scope, nothing conversational while terms are open or agreed, and `inform` only after the commit), the committer rule, a commit's ratification records (`ratified`, valid until `ratified_until`), the thread limit (`max_thread_messages`), and how threads end: `ack` `completed` (never for agreed terms), a `decline` of the first message, a proposal or agreed terms (a `decline` of a later question leaves the thread open), and expiry (in `negotiating` and `agreed`, only a proposal or an accept extends it; never for a committed thread). Turns with a `body` are also checked against the window rule of `alp.availability/1` (`schema_invalid`). A turn naming an id no accepted turn has names a message the broker doesn't hold. |
| `ledger/matching-ledgers.json` | Two principals' ledgers for one envelope: entry hashes, each entry's salt (derived from a TEST-ONLY tag here; a broker draws it at random), the chain, and the cross-references through the receipt. |
| `delivery/sanitize.json` | Delivery sanitizing of free text (spec 12.1.6), including prompt-injection cases. |

## Conventions

- Pointers in vectors are envelope-relative (`/body/...`, `/note`), and pointer lists are sorted.
- Hashes are `sha256:` followed by base64url without padding, over the JCS form.
- Ids are ULIDs derived deterministically from a tag, so adding a case never changes another case's ids.

## Checking an implementation

Run the vectors through your implementation's own code paths: parse, canonicalize, verify, evaluate. A failing vector is a bug in the implementation or in the vector; please report it (see [CONTRIBUTING.md](../CONTRIBUTING.md)). The steward's generator and independent checker are described in [tools/spec/README.md](../tools/spec/README.md).
