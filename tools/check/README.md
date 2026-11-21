# alp-check

The conformance vectors are how an implementation checks its own logic: you run them through your own code paths, as [vectors/README.md](../../vectors/README.md) describes. `alp-check` is the complement for a running broker. You point it at your domain, or at a broker in the Local profile (terms are defined below), and it reports what it can observe from outside, with no credentials, against the Agent Liaison Protocol (ALP) v0.1 specification ([spec/alp-v0.1.md](../../spec/alp-v0.1.md)).

It checks a part of the specification, and every report says which part. A report with no failures does not mean an implementation conforms. Section 13.1 says what claiming a class means: an implementation claims one or more classes, names the protocol version, and passes the vectors that apply to it. [CONFORMANCE.md](../../CONFORMANCE.md) lists every numbered requirement with the vectors that exercise it and the checks below that observe part of it.

Every check cites a section of the specification and quotes the sentence it enforces, word for word; a quote that joins two parts of a section with … has each part word for word, in order. A test fails if a quote does not appear in that section.

Terms, as the specification uses them:

- **Local profile** (Section 3.3): one organization's broker serves its own people, with no domain document and no federation listener. Such a broker is checked with `--broker`.
- **Domain document** (Section 4.2): the JSON file at `https://<domain>/.well-known/alp.json` (or `https://alp.<domain>/.well-known/alp.json`) that names a domain's brokers.
- **JWKS** (JSON Web Key Set, RFC 7517; Section 4.8): the set of public keys a broker publishes at its `jwks_uri`.
- **Pinned**: a domain pins a broker's key by listing the key's RFC 7638 thumbprint in that broker's `jkt` list in its domain document (Section 4.8 rule 1). Peers ignore keys that are not pinned.
- **Protected resource metadata** (RFC 9728) and **authorization server metadata** (RFC 8414): the JSON documents that tell an agent where and how to sign in to a broker's MCP endpoint or REST mirror (Section 5.6). **PKCE** (Proof Key for Code Exchange, RFC 7636) is part of that sign-in; ALP allows only its `S256` method.
- **Federation inbox** (Section 12.2): the URL where other brokers post envelopes to this broker.
- **Acceptance steps** (Section 12.2.4): the checks a receiving broker runs on each envelope, in order. Step 0 is structure (size, parsing, version, schema, delegate ids, lifetime, clock); step 1 is the sender's domain document and the signature.

`alp-check` is licensed under Apache-2.0.

## Running it

You need Node.js 22.18 or later.

```sh
cd tools/check
npm ci                                   # ajv 8.20.0 and ajv-formats 3.0.1, pinned

node check.mjs example.org               # a domain that federates: everything is discovered from its document
node check.mjs --broker https://broker.example.org \
  --mcp https://broker.example.org/mcp --rest https://broker.example.org/rest
                                         # a Local-profile broker, which publishes no domain document
```

The first form fetches the domain document and checks every broker entry it names. The second form checks the URLs you give: `--mcp`, `--rest`, `--inbox` and `--jwks`, at least one of them. In the second form there is no domain, so the domain document and DNS checks are skipped, and so are the two key checks that need a document's pins.

| Option | Effect |
|---|---|
| `--json` | Print the report as JSON. |
| `--only <id or prefix>` | Run only the checks whose id starts with this, for example `--only inbox` or `--only document.schema`. Repeatable. Only the requests those checks need are sent. |
| `--timeout <seconds>` | How long to wait for each answer: default 10, at most 60. |
| `--no-inbox-probes` | Send nothing to the inbox. The inbox checks are then skipped. |
| `--dev-map '<json>'` | Development and CI only. Maps published `https` origins of reserved names (RFC 2606: `.example`, `.test`, `.invalid`, `.localhost`, `example.com`, `example.net`, `example.org`) to `http://127.0.0.1:<port>` or `http://[::1]:<port>` (a port from 1 to 65535 other than 80, without leading zeros), the same idea as the development host map of Section 4.3. With a map, alp-check contacts only the origins the map names, over plain HTTP, and resolves no name. The report's first line says the map is in use, and the TLS and DNS checks are skipped, never passed. |
| `--help` | Show the usage. |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No required check failed and none was left undecided. This means only that nothing this version checks from outside was found wrong. Skipped checks do not change the code; when required check results were skipped, the report says how many, and the SKIP lines say why (for example, an inbox that answers every unsigned probe with 401, or `--no-inbox-probes`). |
| 1 | A required check failed. |
| 2 | A usage error. |
| 3 | An error of alp-check itself. |
| 4 | No required check failed, but at least one required check could not be decided (a rate limit, a temporary failure, no usable answer), or was skipped because one could not. The run says nothing about those checks; try again later. |

A failed recommended check is a warning and does not change the exit code.

## Reading the report

Each check gives one line per subject: the domain, a broker entry, an endpoint or an authorization server. The results are:

- `PASS`: the behaviour matches the quoted sentence.
- `FAIL`: a required check found behaviour that differs from the sentence. The report then quotes the specification and says what was sent, what came back and what was expected.
- `WARN`: a recommended check found such behaviour, with the same details.
- `WARN?`: the checker could not decide, and says why. This is never a failure. It happens when there is no usable answer (a timeout, a connection or TLS failure, an answer over 256 KiB, an encoded answer), when the answer says "not now" (429 or any 5xx, 500 included, in every family, unless it is an ALP error that answers the probe itself, such as 503 `discovery_failed` for a sender's domain that cannot exist), and when the run reached its request limit. A document found only at the second location after a 429, a 5xx, a timeout or a refused connection at the first is undecided too: a peer stops at the first location until a retry succeeds, and the answer may be temporary or the checker's own network. After a certificate that does not validate at the first location, it is a failure instead: Section 4.3 stops every peer there. A certificate that does not validate at the second location, which a peer uses after a 404, a 410 or no address records at the first, is decided too. Every peer sees the same certificate (unless the network alp-check runs on intercepts TLS), so a certificate that does not validate at whichever location a peer uses for the domain document is the only TLS failure alp-check decides: everywhere else, on a broker's host too, and for `document.tls` when the failure is not a certificate failure, a TLS failure is undecided.
- `ERROR`: alp-check itself failed while running the check. This says nothing about the target, and the run exits 3; please report it.
- `SKIP`: the check did not run, with the reason: a prerequisite failed (named by its check id), the option to probe was off, the target has no such endpoint, or the inbox answered every unsigned probe with 401. A failed prerequisite makes the checks that depend on it skip; it never turns them into failures. If every probe sent to an inbox is answered 401, whatever the body, every probe check for that inbox and `inbox.error-shape` skip with the reason "this inbox answers unsigned requests with 401; Section 12.2.2 lets a broker require signed requests, and alp-check does not sign requests", and the exit code is not affected. If some probes to an inbox are answered 401 and others are judged normally, each 401 probe is undecided instead ("answered this probe with 401 while other unsigned probes to the same inbox were judged"), and the run exits 4; `inbox.error-shape` judges only the other answers, and its result line ends with "Not judged:" and the number of 401 answers it set aside, so that a `PASS` there never reads as covering them.

After the checks come a summary by family; the number of required check results that failed; the number that could not be decided, together with those skipped because of them (a run never says only "No required check failed" when some were undecided); when none failed and none was undecided, "No required check failed and none was left undecided." and the number of required check results that were skipped for any other reason; the number of recommended warnings; how many checks the request limit stopped (if any); the Section 13 requirements this run observed in part (a requirement is listed only when at least one of its checks was decided), and a fixed paragraph saying what the tool does not check. A run with `--broker` does not list the requirements that apply only when a broker federates. With `--json`, each result also carries its level, its basis, the quoted sentence and the requirement ids, and the summary carries the same counts (`required_failed`, `required_undecided`, `required_skipped_after_undecided`, `required_skipped`).

## Levels and their basis

Each check is either required or recommended, and the report says why, for example `required (MUST, Section 4.2)`. A failed required check is a failure; a failed recommended check is a warning. The basis is one of three:

- **A key word.** The quoted sentence holds a key word of BCP 14 in capitals: `required (MUST, Section 4.2.1)`, `recommended (SHOULD, Section 4.7)`. The word MUST appears in a report only for a check whose quoted sentence holds it.
- **Stated.** The quoted sentence states the behaviour as a fact, with no key word, in a section whose maturity is Core or Experimental: `required (stated in Section 4.8)`, `required (stated in Section 12.2.3, Experimental)`. Some rules of Section 4.3 bind the party that fetches a document, not the server; a check on what a server serves that rests on such a rule is recommended, and its warning explains that a peer following Section 4.3 would fail to read what is served: `recommended (stated in Section 4.3, as a rule for the fetching peer)`. The validity rules of Section 4.2.1 bind the fetching broker too ("a broker MUST treat the domain as having no valid document"), but a document that peers must treat as absent leaves the domain without the document Section 4.2 has it publish, so those checks are required: `required (MUST, Section 4.2.1, as a rule for the fetching broker)`.
- **A referenced rule.** The rule is in a document that the quoted ALP sentence adopts, and the report quotes that document's sentence too: `required (RFC 9728 Section 3.3, adopted by Section 5.6)`.

One check, `keys.no-unpinned-federation`, quotes a MUST NOT sentence and is still recommended, because the sentence can be read two ways (see below). One check, `signin.as-metadata`, prints the basis of the part that failed: when no RFC 8414 metadata is served, `required (stated in Section 5.6)`, from "The authorization server publishes RFC 8414 metadata"; when its `issuer` differs, the MCP authorization specification's rule.

## The checks

| Check | Level | Basis | Section | What it expects |
|---|---|---|---|---|
| `document.found` | required | stated | 4.2 | A peer that follows Section 4.3 finds the domain document: status 200 at `https://<domain>/.well-known/alp.json`, or at `https://alp.<domain>/.well-known/alp.json` after the first location answers 404 or 410 (or its name has no address records). A redirect, another status or a certificate that does not validate at the first location fails, even when the second serves the document; a 429, a 5xx, a timeout or a refused connection there is undecided. A certificate that does not validate at the second location, when a peer goes on to it, fails too. |
| `document.fallback` | recommended | stated, for the fetching peer | 4.3 | Location 1 serves the document, or answers 404 or 410 (or its name has no address records), so that a peer goes on to location 2. A redirect, an error or another page at location 1 stops every peer there. |
| `document.tls` | recommended | stated, for the fetching peer | 4.3 | The document is served over HTTPS with a certificate valid for the host, at whichever location a peer uses; a certificate that does not validate gives a warning. Undecided on a TLS failure that is not a certificate failure. Skipped with `--dev-map`, and when no location a peer would use served the document. |
| `document.content-type` | recommended | stated, for the fetching peer | 4.3 | A JSON content type: `application/json` or `application/<name>+json`. |
| `document.size` | recommended | stated, for the fetching peer | 4.3 | At most 64 KiB. |
| `document.schema` | required | MUST, for the fetching broker | 4.2.1 | JSON, valid against `schemas/domain-document.schema.json`. |
| `document.domain-matches` | required | MUST | 4.2 | `domain` is the domain asked for. |
| `document.unique-ids` | required | MUST, for the fetching broker | 4.2.1 | No two entries share an `id`. |
| `document.one-wildcard` | required | MUST, for the fetching broker | 4.2.1 | At most one entry has `"principals": "*"`. |
| `document.no-overlap` | required | MUST, for the fetching broker | 4.2.1 | No address is in two explicit lists. |
| `document.addresses-on-domain` | required | MUST, for the fetching broker | 4.2.1 | Every explicitly listed address is on `domain`. |
| `document.urls-on-origin` | required | MUST, for the fetching broker | 4.2.1 | `inbox`, `jwks_uri`, `mcp`, `rest` and `operator_statement` are on the entry's own origin. |
| `document.revoked-not-pinned` | recommended | stated, for the domain | 4.8 | No thumbprint in `revoked_jkt` is still pinned in a `jkt` list (peers refuse the key anyway). |
| `keys.served` | required | stated | 4.8 | The JWKS is served with status 200 at `jwks_uri`. |
| `keys.content-type` | recommended | stated, for the fetching peer | 4.3 | The JWKS has a JSON content type. |
| `keys.size` | recommended | stated, for the fetching peer | 4.3 | The JWKS is at most 64 KiB. |
| `keys.schema` | required | stated | 4.8 | The JWKS is valid against `schemas/jwks.schema.json`. |
| `keys.current-key-pinned` | required | stated | 4.2.1 | At least one thumbprint the entry pins is a `federation` key in the JWKS. Other pinned thumbprints are reported as notes. |
| `keys.no-unpinned-federation` | recommended | MUST NOT, under one reading | 4.8 | Every `federation` key in the JWKS is pinned in this domain's entry for the broker. Recommended, because Section 4.8 rule 1 can be read two ways (see below). |
| `keys.kid-thumbprint` | recommended | RECOMMENDED | 4.8 | Each key's `kid` is its RFC 7638 thumbprint. |
| `dns.txt-grammar` | recommended | stated | 4.7 | When `_alp.<domain>` has TXT records, there is one, and it is `v=ALP1; id=<1 to 32 letters and digits>`. Skipped when there is no record, since it is optional. |
| `dns.txt-id-serial` | recommended | SHOULD | 4.7 | The record's `id` equals the document's `serial`. |
| `signin.prm` | required | RFC 9728 Section 3.3 | 5.6 | Protected resource metadata is served for the MCP endpoint and for the REST mirror, and its `resource` is what RFC 9728 ties to where it was found: the endpoint URL at the location with its path or through the challenge, the origin at the location without a path. For the REST mirror the REST base URL also passes. |
| `signin.prm-authorization-server` | required | the MCP authorization specification (revision 2026-07-28), "Authorization Server Location" | 5.6 | The MCP endpoint's metadata names at least one authorization server. For the REST mirror's metadata this is a note. |
| `signin.prm-scopes` | required | stated | 5.6 | That metadata's `scopes_supported` includes `read` and `send`; other values are notes. |
| `signin.as-metadata` | required | the MCP authorization specification (revision 2026-07-28), "Authorization Server Metadata Discovery"; stated when not served | 5.6 | The authorization server serves RFC 8414 metadata whose `issuer` is the identifier its well-known location was built from. When no such metadata is served, the failure rests on Section 5.6's own sentence; a different `issuer` fails the MCP authorization specification's rule. |
| `signin.oidc-discovery` | recommended | SHOULD | 5.6 | It also serves OpenID Connect discovery, with the same `issuer` (the comparison follows the same MCP sentence). |
| `signin.pkce-s256` | required | MUST | 5.6 | `code_challenge_methods_supported` is exactly `["S256"]`. |
| `signin.iss-parameter` | required | MUST | 5.6 | `authorization_response_iss_parameter_supported` is `true`. |
| `signin.cimd` | required | MUST | 5.6 | `client_id_metadata_document_supported` is `true`. |
| `signin.revocation` | recommended | SHOULD | 5.6 | The metadata names a `revocation_endpoint`. |
| `binding.mcp-challenge` | required | stated | 5.6 | An MCP request with no token gets 401 and `WWW-Authenticate: Bearer` with `resource_metadata` and `scope`. |
| `binding.rest-challenge` | required | stated | 5.6 | The same for `POST {rest}/alp_whoami`. |
| `inbox.version` | required | stated | 16 | An envelope with `"alp": "0.0"` is refused with `unsupported_version`. |
| `inbox.strict-json` | required | MUST | 8.3 | An envelope with a duplicate member name is refused with `bad_envelope`. |
| `inbox.schema` | required | stated | 12.2.4 | An envelope with no `broker_sig` is refused with `bad_envelope`. |
| `inbox.lifetime` | required | stated | 12.2.4 | An envelope that expires more than 7 days after it was created, and one that expires before it was created, are each refused with `bad_envelope`. |
| `inbox.created-ahead` | required | stated | 12.2.4 | An envelope created one hour ahead of the checker's clock is refused with `bad_envelope`. |
| `inbox.delegate-owner` | required | stated | 12.2.4 | An envelope whose `from.delegate` belongs to another address, and one whose `to.delegate` does, are each refused with `bad_envelope`. |
| `inbox.unknown-sender-domain` | required | stated | 12.2.4 | An envelope from a sender on a domain that cannot exist is refused with `discovery_failed` or `broker_not_authorized`. |
| `inbox.error-shape` | required | stated | 12.2.3 | Each of those refusals is an unsigned error: the registry's status for its code, `{ "error": { "code", "message" } }`, and no receipt. A 401 is not judged (Section 12.2.2), and the result line says how many 401 answers were set aside. |
| `inbox.retry-after` | required | stated | 12.2.3 | Every 429 or 503 answer carries `Retry-After`, including a front server's answer at the inbox URL, which the other inbox checks set aside. |

The sentence each check quotes is in [catalog.mjs](catalog.mjs), and in every failure the report prints.

## What it sends

alp-check sends only the requests below. Each is an ordinary HTTPS request with `User-Agent: alp-check/0.1 (+https://github.com/AgentLiaisonProtocol/agentliaisonprotocol)`. In the commands above, `example.org` stands for your own domain and `broker.example.org` for your own broker.

**Which hosts it contacts.** You choose the domain, or the broker's URLs. In the first form the domain's document then chooses the rest: alp-check contacts the two well-known locations of the domain, the origin of each broker entry the document names, and the authorization server that each entry's protected resource metadata names. A document can name brokers that someone else runs for the domain (a Hosted Broker, for example), and each of them receives the requests listed for a broker entry below.

**DNS.** One TXT query for `_alp.<domain>`, in the first form only, and not with `--dev-map`.

**The domain document.** `GET https://<domain>/.well-known/alp.json`, and `GET https://alp.<domain>/.well-known/alp.json` when the first does not answer 200. Both carry `Accept: application/json`, and `Cache-Control: no-cache` as Section 4.3 rule 4 asks of a peer.

**For each broker entry**, on that entry's own origin only (in the second form, on the origins of the URLs you gave):

- `GET` the entry's `jwks_uri`.
- `POST` to the `mcp` URL: a JSON-RPC `initialize` request (protocol revision 2025-11-25) with no token. Without a token, a broker answers 401 and does nothing.
- `POST {rest}/alp_whoami` with the body `{}` and no token.
- `GET` the protected resource metadata of the MCP endpoint and of the REST mirror, at the first of these that answers 200 with a JSON object: the `resource_metadata` URL of the 401 challenge, if it is on the endpoint's origin; `https://<host>/.well-known/oauth-protected-resource<path>`; `https://<host>/.well-known/oauth-protected-resource`.
- Nine `POST`s to the `inbox`, one envelope each, described below.

**For each authorization server** that protected resource metadata names first: `GET` its RFC 8414 metadata (`https://<host>/.well-known/oauth-authorization-server<path>`) and its OpenID Connect discovery document (`<issuer>/.well-known/openid-configuration`). The authorization server may be on another origin; nothing else there is fetched.

**The inbox probes.** Each is an envelope the specification requires a broker to refuse before any person or relationship is involved: it fails acceptance step 0, or step 1 because its sender is on a domain that cannot exist. Apart from the one defect it tests, each is valid against its schema, with fresh ids and timestamps. Eight are `connection_request` control envelopes of about 1 KB; the `to.delegate` probe is a `request` message of about the same size, from an agent of the sender, because a control envelope's `to` has no `delegate`.

- Sender: `alp:alp-check-<16 hex digits>@alp-check-<16 hex digits>.invalid`, with `origin_broker` `https://broker.alp-check-<16 hex digits>.invalid`. The `.invalid` name cannot exist (RFC 2606), so no broker can find a document for it.
- Recipient: `alp:alp-check-<40 hex digits>@<domain>` (in the second form, `@<broker host>`), an address nobody holds. A broker that wrongly accepted a probe would still reach no person.
- `broker_sig`: a protected header (`alg`, `kid` `alp-check-unsigned`, `typ`) and a signature of 64 zero bytes. alp-check signs nothing, and nothing it sends can verify.
- The defects, one per probe: `alp` is `"0.0"` (which also fails the schema, since the schema fixes `alp`; Section 16 still names `unsupported_version` for it); the member `alp` appears twice; `broker_sig` is missing; `expires_at` is 7 days and 1 hour after `created_at`; `expires_at` is 30 seconds before `created_at` (which is 60 seconds ahead, within the 300 seconds allowed); `created_at` is one hour ahead; `from.delegate` names an agent of another address; `to.delegate` names an agent of another address; none (the sender's domain is the only obstacle).

The target's operator may see these requests in its logs, and its broker may record them as security events. Run alp-check against domains and brokers you operate, or are allowed to test.

**Limits.** HTTPS only, except through `--dev-map`. No redirect is followed: a redirect is reported. Outside `--dev-map`, no request goes to a host written as an IP address, to `localhost` or a name under it, to a single-label name, or to a special-use name (`.local`, `.internal`, `.home.arpa`, `.onion`, `.alt`, `.arpa`, `.example`, `.invalid`, `.test`); one trailing dot is removed before these tests. Every other name is resolved once, and the host is refused if any address it resolves to is not a public unicast address: private, loopback, link-local, shared, multicast, reserved, documentation and benchmarking addresses are refused, and so is an IPv4-mapped, NAT64 or 6to4 address that carries one of them. The connection goes only to the addresses that were checked, and no connection is reused. This follows rule 2 of Section 4.3, the rule for a broker's own fetcher, with two differences: alp-check accepts an IPv4-mapped IPv6 address that carries a public IPv4 address, which rule 2 refuses, and it contacts any port a URL names, where rule 1 has a peer use port 443 only. A refused host is reported, never contacted. A request made for one broker entry goes only to that entry's own origin; a URL a document names on another origin is reported, not fetched. TLS certificates are always verified. alp-check asks for no content encoding and does not read an encoded answer. It reads at most 256 KiB of a response and waits at most the timeout for each exchange, the name lookup included. It makes at most 80 HTTP requests in a run, one at a time, and asks for the same URL with `GET` only once; once it knows the broker entries, each entry gets an equal share of the requests that are left, and the report says how many checks the limit stopped. It sends no credentials and no cookies, and it signs nothing.

**What it prints.** At most 400 characters of any response body in one field of the report, with control characters and the format characters that can hide or reorder text shown as escapes.

## What it does not check

This version needs no credentials and acts as no peer, so it leaves out:

- **Anything that needs a token**: the tool list and its descriptions, tool results and their schemas, the REST mirror's behaviour, sanitizing and the untrusted-content wrapper, DLP, the own-agent path, token lifetimes and audiences, refresh-token rotation, and personal access tokens.
- **Anything that needs the checker to act as a peer broker with its own domain and keys**: signatures, pinning, `typ`, audience, expiry, replay and duplicates, receipts, and the recipient-side steps. Of acceptance steps 1 to 6, it sends only the probe whose sender's domain cannot exist.
- **Everything not observable from outside**: ledgers, the security event stream, grants and their sealing, connection approval, ratification, kill switches, retention, organization policy and the operator statement's content.
- **The 64 KiB body limit** (Section 8.10). The specification does not say at which acceptance step the 64 KiB limit applies, so a broker may refuse an oversized probe from an unknown sender for the sender first (step 1); alp-check cannot require `body_too_large` and does not probe it.
- **Parts of the checks it does run**: it does not see authorization responses (so not whether `iss` is in each one), it checks only the first authorization server a resource names, it does not judge the 5-second fetch limit (its own network is not a peer's), it does not watch a `serial` increase over time, and it does not know which class a broker claims, so it does not check that a Hosted or Provider Broker publishes an operator statement.

## Where the specification is silent or can be read two ways

A check asserts only what the text says. These are the places where the text is silent or can be read two ways, and what alp-check does about each. None of them is a judgement of which reading is right; each is a question for the specification.

- **A sender's domain with no document** (Sections 4.4, 8.7, 12.2.4 step 1). Section 4.4 says a broker with no valid document for a domain refuses envelopes from it with `discovery_failed`. Section 8.7 gives `broker_not_authorized` for an origin broker the document does not list, and the acceptance vectors expect that code for a domain with no document. `inbox.unknown-sender-domain` passes either code.
- **Unpinned federation keys and the order of rotation** (Section 4.8 rules 1 and 4). "A broker MUST NOT publish federation keys that the domains listing it haven't pinned" can mean that every listing domain pins every key, or that every key is pinned by some listing domain. Rule 4 ends with the domains unpinning the old key, without saying that the broker stops publishing it first. `keys.no-unpinned-federation` checks the first reading on the one domain it sees, and only warns.
- **Where the 64 KiB body limit is applied** (Sections 8.10, 12.2.4, 18.3). The limit and its code (`body_too_large`) are given, but the specification does not say at which acceptance step the 64 KiB limit applies, so a broker may refuse an oversized probe from an unknown sender for the sender first; alp-check cannot require `body_too_large` and does not probe it.
- **A certificate that does not validate where a peer reads the domain document** (Section 4.3). Section 4.3 calls any failure at location 1 other than 404, 410 or no address records, a TLS failure included, a temporary failure, after which a peer does not go on to location 2. alp-check reads a certificate that does not validate there as decided rather than temporary, because every peer sees the same certificate: `document.found` fails when the document is only at the second location behind it, and `document.fallback` and `document.tls`, which are recommended, warn. It reads a certificate that does not validate at location 2, which a peer uses after 404, 410 or no address records at location 1, the same way: `document.found` fails and `document.tls` warns. Other TLS failures at either location are undecided, as TLS failures are everywhere else.
- **A wrong content type, an envelope over 1 MiB, a method other than POST** (Sections 12.2.1, 12.2.4 step 0). The inbox takes `application/json` by `POST`, but no status or code is given for another content type or method. An envelope over 1 MiB fails step 0, whose codes make it `bad_envelope`. alp-check sends none of these.
- **How an inbox that requires signed requests refuses an unsigned one** (Section 12.2.2). An inbox may require signed requests from its peers, but no code, status or form is given for refusing a request without a signature, and Section 12.2.3's unsigned error is for an envelope that can't be authenticated at steps 0 and 1. alp-check signs nothing. If every probe sent to an inbox is answered 401, every probe check for that inbox is skipped with the reason "this inbox answers unsigned requests with 401; Section 12.2.2 lets a broker require signed requests, and alp-check does not sign requests", `inbox.error-shape` does not judge those answers, whatever their body, and the exit code is not affected. If some probes to an inbox are answered 401 and others are judged normally, each 401 probe is undecided ("answered this probe with 401 while other unsigned probes to the same inbox were judged"), which makes the run exit 4, and `inbox.error-shape` reports the 401's shape as a note and says on its result line that the 401 answers were not judged.
- **An unknown `alp` value** (Sections 12.2.4 step 0, 16). The probe also fails the schema, which fixes `alp` to `"0.1"`. Section 16 names `unsupported_version` for an unknown value and step 0 lists the version before the schema, so `inbox.version` requires `unsupported_version`.
- **"A JSON content type"** (Section 4.3 rule 3). The types are not listed. alp-check accepts `application/json` and any `application/<name>+json`, with any parameters.
- **The 64 KiB limit for a key set** (Section 4.3). The first paragraph names the JWKS among what the fetcher reads, and rule 4 says "per document". alp-check applies the limit to key sets too, as a recommended check.
- **Pinned thumbprints that are not in the key set** (Section 4.2.1, `jkt`). The list holds "the current key and the next one", and nothing says the next key is published before it signs. `keys.current-key-pinned` requires one pinned federation key in the set and reports the others as notes.
- **A revoked key that is still pinned** (Section 4.8 rule 5). The compromise procedure removes the thumbprint from `jkt`, but with no key word, and Section 4.2.1 does not make such a document invalid. `document.revoked-not-pinned` only warns.
- **The TXT record's spacing** (Section 4.7). The example has one space after the semicolon; other spacing is not addressed. alp-check accepts any number of spaces there, and joins a record split into several strings.
- **The unsigned error's members** (Section 12.2.3). The text shows `{ "error": { "code", "message" } }` without saying whether other members may appear. Members beyond these are notes.
- **`scopes_supported`** (Section 5.6 items 7 and 8). Item 8 lists `["read", "send"]`; item 7 issues refresh tokens for `offline_access`, which the MCP authorization specification says a server SHOULD NOT list. alp-check requires `read` and `send`, in either order, and reports other values as notes.
- **The REST mirror's protected resource metadata** (Section 5.6, RFC 9728 Section 3.3). RFC 9728 ties `resource` to where the metadata was found, which for a challenge from `POST {rest}/alp_whoami` is the tool's URL; Section 5.6 item 6 binds tokens to the REST base URL. `signin.prm` accepts either for the REST mirror. RFC 9728 also makes `authorization_servers` optional, and the MCP authorization specification's rule that requires it covers the MCP endpoint, so for the REST mirror its absence is a note.
- **Duplicate member names in a domain document** (Section 8.3). The strict parse is required of received objects, in a section about envelopes; whether it covers domain documents is not said. A document with duplicate names gets a note, not a failure.

## Tests

```sh
node --test tools/check          # from the repository root
cd tools/check && npm test       # the same tests
```

The tests never open a socket and never resolve a name. `test/fake-broker.mjs` is an in-memory domain and two brokers, with the shape of `fetch`, written from the specification. It behaves correctly by default, has variants the specification allows, and has one switch per fault, such as a document with two `"*"` entries, a JWKS with an unpinned federation key, a 401 with no `resource_metadata`, or an inbox that accepts a duplicate member name. The tests check that:

- every quote appears word for word in the section it names (each part of a two-part quote, in order, starting and ending at word boundaries), each check's level matches its basis, and every requirement id exists in Section 13;
- every check passes on the correct fake, and fails (or warns, for a recommended check) under at least one fault; each fault makes exactly the checks listed for it fail, for the subject and reason listed, both for a domain and with `--broker`, so no check fails only because an earlier one did;
- no variant the specification allows gets a failure: among them an inbox that answers every unsigned probe with 401, with an ALP error or with plain text (its probe checks and `inbox.error-shape` are skipped, and the run exits 0), rate limits and server errors (which exit 4, as undecided), a key set during rotation, and a REST mirror whose metadata is found through the tool's path;
- no redirect is followed, no response is read past 256 KiB, no run makes more than 80 requests, each broker entry gets its share of them, and nothing outside the allowed origins is contacted;
- IP addresses, loopback, single-label and special-use names are refused, and a host that resolves to any address that is not public is refused before a connection: `test/transport-stub.mjs` stands in for the resolver and for `node:https`, so alp-check's own transport and its lookup run without a socket;
- each inbox probe is valid except in the one respect it tests;
- [CONFORMANCE.md](../../CONFORMANCE.md) is current;
- the scripts in `ci/` build a valid domain document from a broker's key set, and judge a run as the next paragraph says.

In CI, [ci/run-against-reference.sh](ci/run-against-reference.sh) runs alp-check against the reference broker with federation on, on one machine through the development host map, and [ci/judge.mjs](ci/judge.mjs) fails the job unless every check passes, for the domain, the broker and its MCP and REST URLs, except the four that its setup cannot exercise (`document.tls`, `dns.txt-grammar` and `dns.txt-id-serial`, since there is no TLS and no DNS on loopback, and `inbox.retry-after`, since no probe gets a 429 or 503 answer). A check that the "Where the reference broker and the specification differ" section of [KNOWN-GAPS.md](../../KNOWN-GAPS.md) records may fail instead, and then must; none is listed now. This shows that the checks' expectations hold for the reference broker, and nothing about any other implementation; the domain document is one the job builds from the broker's own keys.

To see a report without a network, run the command against the fake: `node tools/check/test/against-fake.mjs`, optionally with `--fault <name>` (the names are in `test/fake-broker.mjs`) and the checker's own arguments.

`requirements.mjs` writes CONFORMANCE.md from Section 13 of the specification: `node tools/check/requirements.mjs`, or `--check` to see whether it is current.
