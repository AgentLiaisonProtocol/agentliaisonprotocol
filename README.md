# Agent Liaison Protocol

*Between people, through their agents.*

MCP connects agents to tools. A2A connects agents to agents. ALP connects people through their agents, under each person's rules.

A leader's dot in his company's ChatGPT workspace, his company's Claude and his personal Muse (Meta) come from three vendors and should work together, but not as equals: confidential board figures may reach his company agents, not his Muse without his say. When an analyst's agent needs something from his, her request shouldn't carry her sensitive fields or need a login to his tools, and his agent shouldn't answer anything that merely claims to be hers. The Agent Liaison Protocol (ALP), an open standard for work between people carried by their agents, handles both: each agent talks only to its own person's broker, which carries only what both people's rules allow.

- **Read the announcement:** [Introducing the Agent Liaison Protocol](announcement/introducing-agent-liaison-protocol.md) (https://agentliaisonprotocol.org)
- **Read the specification:** [spec/alp-v0.1.md](spec/alp-v0.1.md)
- **Run the demo:** see [Try it](#try-it)
- **Check the status:** [what's tested and what isn't](#status), and [KNOWN-GAPS.md](KNOWN-GAPS.md)

Version 0.1, a draft for implementers, includes the specification, its JSON Schemas and conformance vectors, a reference broker built to sign people in through their organization's OpenID provider (such as Microsoft Entra ID), a one-command demo, and a bridge kit for connecting the agents people already use. On November 7, 2026, real agents were tested on a development broker with test identities: Claude and Claude Duet connected as one test person and Muse as another, and Duet and Muse exchanged a typed request and its reply. Lucaryin is the author and initial steward and intends to move the specification to a neutral foundation. Anyone can implement the specification. The reference broker in `reference/` has its own license, not the root Apache-2.0 [LICENSE](LICENSE): it is source-available under FSL-1.1-ALv2, free for any organization to use, modify and run for itself ([License](#license)).

## The idea

Agents never talk to each other directly. Each agent talks only to its own person's **home broker**. Home brokers carry only typed messages that both people's rules allow, prove to each other whom they speak for, and each keeps a ledger its person can read.

## What it guarantees

Stated as precisely as the specification supports them (spec Section 1.4):

1. **On the ALP channel, nothing leaves a person's side that their rules don't allow, and nothing reaches their agent from anyone they, or their organization's policy, haven't approved.** Disclosure is checked field by field at the sender's broker before anything leaves, and again at the recipient's broker before anything is delivered. Free text is off unless the recipient opts in, capped at 280 characters and checked for sensitive data.
2. **No agent gets into another person's accounts.** Each agent signs in only to its own person's broker, with that person's own sign-in, using short-lived, audience-bound tokens with rotating refresh tokens, or a revocable personal access token of at most 30 days for organization accounts (an organization can forbid them in its list of agents). No agent ever holds another person's tokens, cookies or sessions.
3. **Identity is proven by the sender's domain and home broker,** never by the message. A broker accepts a message only from the sender's home broker, as named by the sender's domain, signed with a key that domain pins. Strangers can only send a connection request, which reaches the person, not their agent.

And what it can't do: ALP can't control what a vendor's agent does with what it reads, or how a vendor stores it. A stolen sign-in or a compromised broker can speak for its own people until it's revoked. Revocation is immediate on the revoking broker and takes effect elsewhere within the cache bound. Notifications only notify; approvals happen on the person's approvals page with a fresh sign-in (in production, a passkey or single sign-on step-up; the reference does the step-up at the organization's identity provider when it signs people in that way, asks for a passkey when it serves the page on its public origin, and otherwise re-checks a test sign-in). See spec Sections 1.5, 14 and 15.

## Two ways in

- **Client mode: no vendor work needed.** A person, or their IT team, adds one custom MCP connector to their agent, pointing at their home broker, and the person signs in with their own account (again each time the grant ends, after at most 30 days for organization accounts). The agent gets seven tools (`alp_send`, `alp_inbox` and so on). The broker enforces the rules, so the guarantees above hold even though the vendor did nothing. It works within each agent platform's own connector rules, which differ: some platforms poll rather than push, some ask the person to confirm each send, and some plans allow only reads. See [bridge-kit/](bridge-kit/) for per-platform notes.
- **Native mode: the vendor builds it in.** A vendor's agent includes the client binding as a Native Client, so no connector is needed and push can live in the vendor's app. In v0.1 the person still approves things on their approvals page; approving inside the vendor's app needs an interface planned for a later version. A provider can also run its own broker for addresses on its own domain.

The two are designed to interoperate: the same addresses, envelopes, scopes, grants and ledgers. Client mode needs a broker that someone runs (your organization's, your own, or a hosted one); it needs no workspace platform and no vendor work.

## The 60-second picture

```text
 Ana's agent ──(her own sign-in)──▶ Ana's home broker ════(signed envelope)════▶ Lee's home broker ──▶ Lee's agent
                                     │ checks Ana's rules                         │ checks the signature, that Ana's
                                     │ and her org's policy;                      │ domain names Ana's broker, and
                                     │ refuses before anything                    │ Lee's own rules; returns a
                                     │ leaves                                     │ signed receipt
                                     ▼                                            ▼
                                 Ana's ledger  ◀──── both record the same hash ────▶  Lee's ledger
```

1. **Addresses look like email:** `ana@example.org`. A domain publishes `/.well-known/alp.json`, naming the broker that speaks for each of its people and pinning that broker's keys.
2. **Inside one organization** (the default), one broker serves everyone, whichever vendor each person's agent comes from, and needs no published domain document. **Across organizations**, brokers federate the way mail servers do.
3. **Relationships** come from the organization's defaults (for example, "analysts may ask leaders for briefings") or from a connection request that the other person approves. Each person's grant says field by field what their agent may disclose and what they accept.
4. **Scopes** type the work: `alp.availability/1`, `alp.meeting/1`, `alp.briefing/1`, `alp.status/1` and `alp.document_request/1`, each with a closed JSON Schema and a classification map.
5. **Threads are conversations.** Either agent can answer, ask a follow-up question, ask back or add an update in the same thread, until one side closes it or it expires; a thread takes up to 200 messages, and a new one continues a longer conversation. Each message is checked by both brokers and recorded in both ledgers, like the first.
6. **Binding commitments**, such as booking a meeting or sharing a document, need both people to ratify the agreed terms on their own broker first.
7. **Both ledgers** record what crossed and cross-reference each other's receipts.

## What's here

| Path | What it is |
|---|---|
| [spec/alp-v0.1.md](spec/alp-v0.1.md) | The normative specification |
| [schemas/](schemas/) | JSON Schemas (2020-12) for every object, the five core scopes, the fixed client-binding tool list ([schemas/client/tools.json](schemas/client/tools.json)) and the REST mirror's OpenAPI document |
| [vectors/](vectors/) | Conformance vectors: canonicalization, signatures, envelope validity, sender-side and recipient-side policy decisions, federation acceptance, threads, ledgers and delivery sanitizing. The keys are TEST-ONLY. |
| [tools/spec/](tools/spec/) | The specification tools: they generate the vectors and the specification's worked examples, and check every schema and vector with an evaluator written independently of the reference broker (`cd tools/spec && npm ci && npm run check`) |
| [reference/](reference/) | The reference broker (TypeScript, Node 22), its tests and the demo ([ARCHITECTURE.md](reference/ARCHITECTURE.md)), under its own license, FSL-1.1-ALv2 ([reference/LICENSE.md](reference/LICENSE.md); see [License](#license)) |
| [bridge-kit/](bridge-kit/) | Client-mode setup: a generic guide, one guide per agent platform, and the instruction snippet for agents |
| [SELF-HOST.md](SELF-HOST.md) | Running your own broker (Docker or Node; file or Postgres store), and what isn't built yet |
| [announcement/](announcement/) | The announcement post |
| [site/](site/) | The announcement page, served at https://agentliaisonprotocol.org |
| [CLAIMS.md](CLAIMS.md) | Every claim the README, the announcement and the bridge kit make, with its evidence or its limit |
| [KNOWN-GAPS.md](KNOWN-GAPS.md) | The known gaps of v0.1 and its reference broker, for implementers and operators to plan around |
| [GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [CHANGELOG.md](CHANGELOG.md) | How the project runs |

## Try it

The reference broker runs on Node 22.18 or later:

```sh
cd reference
npm ci
npm run demo              # the whole story over real HTTP on your machine (below)
npm run demo:federation   # federation in detail: replays, a broker removed from its domain's document, revocation
npm test                  # the test suite, including every conformance vector in vectors/
```

`npm run demo` starts real HTTP servers on 127.0.0.1 and prints a numbered transcript. Agents from different vendors join as client-mode clients through the real OAuth flow (or a personal access token). In steps 0 to 6 the fictional example.org's people live on two hosted brokers that its domain document names (the hosted neutral profile, spec Section 3.3; the Hosted Broker class, Section 13.5), with no workspace anywhere.

0. One person's three agents of different trust (a company workspace agent, a company assistant and a personal agent) work together through his broker. A confidential field reaches the company agents but waits for the person before the personal one gets it.
1. A briefing request crosses between the two brokers.
2. A confidential financial figure is stopped before it leaves.
3. A rogue broker claiming to speak for the sender is refused, as are a token claiming another person and a replay.
4. An outsider's message becomes a connection request to the person, never reaching their agent.
5. The recipient's agent reads its inbox and checks the signatures against the published keys. The two agents then continue the conversation in the same thread, a follow-up question and its answer, until one of them closes it.
6. Both ledgers point at each other.
7. The same story on example.org's own broker, including a meeting both people ratify on their own approvals pages. (The in-organization Local profile, with no domain document at all, is what the test suite's Act 1 runs.)
8. A person whose agent has no connector support approves on their approvals page, from a notification that only notifies.

To run your own broker, see [SELF-HOST.md](SELF-HOST.md); to evaluate `npm start` with scripts on one machine, before any TLS or identity provider, follow [Evaluate on one machine](SELF-HOST.md#evaluate-on-one-machine). The broker can sign people in through their organization's OpenID provider, such as Microsoft Entra ID (binding each person to the provider's issuer and subject, for Entra the tenant and object id; app roles or groups as policy groups; a re-check at the provider at every token refresh). The demo and `npm run dev` use test identities. Implementers can test against `vectors/`; [vectors/README.md](vectors/README.md) explains the format, and the reference runs every vector in its own test suite.

## Status

Version 0.1.0 is a draft for implementers, and v0.x releases can change incompatibly. The reference broker is new code and hasn't had an independent security review. No vendor, foundation or standards body has endorsed ALP. Every section of the specification carries a maturity label:

- **Core:** stable enough to implement now. Addresses, identity, the OAuth profile, grants and organization policy, both evaluation algorithms, scopes, envelopes, threads and ratification, delivery, ledgers, the client binding and the web view.
- **Experimental:** specified and testable, more likely to change: federation between brokers, push adapters, the Native Client and the Provider Broker.
- **Future:** planned for v0.2 (spec Section 19).

Client mode was tested with several real agent products together on November 7, 2026: on a development broker with test identities, Claude and Claude Duet (through a custom connector) and Muse (through the REST API) connected as two test people and exchanged a request and its reply. ChatGPT, Grok, Gemini and Microsoft 365 Copilot haven't been connected yet. [bridge-kit/README.md](bridge-kit/README.md#tested-with-real-agents) says what was shown and what wasn't.

Sign-in through an organization's OpenID provider is built and tested against a standard OIDC provider, and was tested once, on November 8, 2026, against a single-tenant Microsoft Entra ID (Free) tenant with test users: Claude on claude.ai connected through it, and the binding to tenant and object id, app roles as policy groups, a fresh sign-in at Entra for each approval and the re-check at each token refresh (about every 10 minutes while the agent is in use) all worked; disabling a user ended their agent's connection at its next refresh, about 8 minutes later. [SELF-HOST.md](SELF-HOST.md#tested-against-a-live-entra-tenant) lists what that test didn't try, such as Conditional Access. The reference broker's web view answers only on the broker host, so with sign-in through an organization's identity provider only people who can reach that host can approve connections, ratify terms or export their ledger; [KNOWN-GAPS.md](KNOWN-GAPS.md) lists this and the other known gaps.

## Get involved

ALP is open to implementers and contributors. Read the [specification](spec/alp-v0.1.md), run the demo, implement it, and tell us what breaks: issues and pull requests are welcome here ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go to hello@agentliaisonprotocol.org, and security vulnerabilities privately to security@agentliaisonprotocol.org ([SECURITY.md](SECURITY.md)), not to a public issue. The licenses below let anyone implement ALP without asking, including in a broker of their own that they sell, and let any organization use, modify and run the reference broker for itself.

## License

Three licenses apply, each to its own paths, as the table below shows. The root [LICENSE](LICENSE) (Apache-2.0) covers only the paths marked Apache-2.0 there. GitHub's license summary reads only the license files at the repository's root, so it doesn't show the reference broker's own license, [reference/LICENSE.md](reference/LICENSE.md).

| Path | What it is | License |
|---|---|---|
| [spec/](spec/) | The specification text | [CC BY 4.0](LICENSE-SPEC) |
| [schemas/](schemas/), [vectors/](vectors/) | The JSON Schemas and the conformance vectors | [Apache-2.0](LICENSE) |
| [tools/spec/](tools/spec/), [bridge-kit/poller/](bridge-kit/poller/) | The specification tools and the bridge kit's code, like any other code outside `reference/` | [Apache-2.0](LICENSE) |
| [bridge-kit/](bridge-kit/) (its other files), [announcement/](announcement/), [site/](site/), and the Markdown documents at the root, such as this README, [SELF-HOST.md](SELF-HOST.md) and [GOVERNANCE.md](GOVERNANCE.md) | Other documentation: the bridge kit, the agent instruction snippet, the announcement and the project's own documents | [CC BY 4.0](LICENSE-SPEC) |
| [reference/](reference/) | The reference broker: its source, tests, migrations, deployment files, Dockerfile and demo | [FSL-1.1-ALv2](reference/LICENSE.md) (Functional Source License, Version 1.1, ALv2 Future License); licensor: Lucaryin LLC, which holds its copyright and is ALP's author and initial steward |

**The specification is an open standard.** Anyone can implement ALP from the specification, schemas and vectors, and use, give away or sell their implementation, a broker included, without asking. The licenses grant those rights on their terms, such as attribution; CC BY 4.0 grants no patent license ([GOVERNANCE.md](GOVERNANCE.md#licenses-and-patents)). Code copied or adapted from `reference/` stays under the reference broker's license until the version it came from becomes Apache-2.0.

**The reference broker is source-available, not open source.** It is free for any organization to use, modify and run for itself; it may not be made available to others in a commercial product or service that substitutes for it or offers substantially similar functionality; and each version becomes Apache-2.0 two years after it is first published. Where this summary and the license differ, the license governs. In the words of [its license](reference/LICENSE.md), a Permitted Purpose is "any purpose other than a Competing Use", and a Competing Use "means making the Software available to others in a commercial product or service that: 1. substitutes for the Software; 2. substitutes for any other product or service we offer using the Software that exists as of the date we make the Software available; or 3. offers the same or substantially similar functionality as the Software." Permitted Purposes specifically include using it "for your internal use and access", "for non-commercial education", "for non-commercial research" and "in connection with professional services that you provide to a licensee using the Software in accordance with these Terms and Conditions." The license also has patent, redistribution and trademark clauses, and its future-license grant reads: "We hereby irrevocably grant you an additional license to use the Software under the Apache License, Version 2.0 that is effective on the second anniversary of the date we make the Software available." Each version counts from its own date: code first published on a given day is also licensed under Apache-2.0 from that day two years later.

Contributions are accepted under CC BY 4.0 or Apache-2.0, as [CONTRIBUTING.md](CONTRIBUTING.md) says; contributions to the reference broker are distributed with it under FSL-1.1-ALv2.

Repository: https://github.com/AgentLiaisonProtocol/agentliaisonprotocol
