# Introducing the Agent Liaison Protocol

**Between people, through their agents.**

*The Agent Liaison Protocol (ALP) is an open standard for work between people, carried by their agents, under each person's rules.*

By Brien Collier, Lucaryin · November 9, 2026

**Read the spec and run the demo: https://github.com/AgentLiaisonProtocol/agentliaisonprotocol**

A leader has three AI agents from three vendors: a dot in his company's ChatGPT workspace, his company's Claude, and Meta's Muse on his personal account. They should work together, but not as equals: his company's agents may see the confidential board figures, and his Muse shouldn't get them without his say. We found no standard way to do that today, let alone between two people or two companies. MCP connects agents to tools. A2A connects agents to agents. ALP connects people through their agents, under each person's rules.

ALP v0.1 includes the specification, its JSON Schemas and conformance vectors, a source-available reference broker built to sign people in through their organization's identity provider (such as Microsoft Entra ID), a one-command demo, and a bridge kit for the agents people already use. On November 7, 2026, we tested the reference's development broker with real agents: Claude and Claude Duet connected as one test person and Muse as another, Duet and Muse exchanged a typed request and its reply, and the broker refused a message claiming another person's address and a request carrying a confidential amount.

## The problem

Now add a second person: an analyst preparing a quarterly review. Her agent, a Claude in her company's workspace, needs the priorities of the leader she reports to, and an hour on his calendar. His dot has both. Three things go wrong at once:

- **Data leakage.** Her agent's request shouldn't carry her draft numbers, and his agent shouldn't answer with more than he would share.
- **Access sprawl.** Her agent shouldn't need a login to his calendar, mailbox or documents to get an answer.
- **Impersonation.** His agent shouldn't respond to anything that merely claims to be hers.

Across organizations it's harder still: different vendors, identity systems and security policies, and neither company will give the other's agent a login. Logging one agent in to another person's tools creates the standing access security teams work to remove, and still doesn't say who is asking.

## Three guarantees

In ALP, agents never talk to each other directly. Each talks only to its own person's **home broker**, and brokers keep three promises:

1. **Nothing crosses that both people's rules don't allow.** Each message type's schema classifies every field, and a field crosses only if the sender's permissions, each side's organization policy and the recipient's rules allow it. Free text is off unless the recipient opts in, capped at 280 characters, checked for sensitive data and labeled untrusted.
2. **No agent gets into another person's accounts.** Each agent signs in only to its own person's broker and never holds another person's tokens, cookies or sessions.
3. **Senders are proven, not claimed.** Identity is proven by the sender's domain and home broker, never by the message. Strangers can only send a connection request, which goes to the person, not the agent.

These hold on the ALP channel: nothing leaves a person's side that their rules don't allow, and nothing reaches their agent from anyone they, or their organization's policy, haven't approved. ALP can't control what a vendor's agent does with what it reads, or how a vendor stores it, and a stolen sign-in or a compromised broker can still speak for its own people until it's revoked.

## How it works: like email

Every person has an address on a domain, such as `ana@example.org`, and each domain that federates publishes, at a well-known HTTPS address, which broker is home for its people. A broker is to an agent what a mail server is to a mail client.

When Ana's agent needs something from Lee's, it hands a typed request to Ana's broker, which checks it against her permissions and her organization's policy, signs it and sends it to Lee's broker. Lee's broker checks that the signer is Ana's home broker, then applies Lee's rules before his agent sees anything. Both sides keep a ledger their person can read, each carrying the other's signed receipt.

One person's own agents work the same way: they write to each other through his home broker, which knows each agent, and how far to trust it, from his organization's list, never from what the agent claims. Each message reaches the dot under a line the broker writes, such as "from your own agent muse (consumer, self-attested)", so the dot can answer Muse differently from Claude. Whatever the dot does, the broker enforces the difference: a confidential field reaches company agents that sign in with a credential only the company holds, and his Muse gets the message without it until he decides on his approvals page.

Organizations can pre-approve relationships among their own people. Anything that commits a person, such as accepting a meeting, needs that person's approval on their approvals page unless given in advance.

## Two ways in, and nobody migrates

**Client mode needs a broker that someone runs (your organization's, your own or a hosted one), but no workspace platform and no vendor work.** The person, or their IT team, adds one custom MCP connector pointing at that broker, and the person signs in with their own account, again each time the grant ends (after at most 30 days for organization accounts). The agent gets a mailbox; the broker enforces the rest. It uses the custom-connector features of Claude (all plans), ChatGPT Business and Enterprise (dots on Business Premium and Enterprise), Grok, Microsoft 365 Copilot and the Gemini app, and Muse can build its own connector to the broker's REST API; the bridge kit lists each product's limits, and [What's tested and what isn't](#whats-tested-and-what-isnt) says which have been tried. Without connector support, the person gets a notification and acts on their approvals page.

Client mode has costs: setup once per person, a confirmation before each send in most products, and replies in minutes or hours where an agent can't receive pushes, as most can't.

**Native mode is for providers.** A provider can build the client side into its agent, so no connector is needed, while the organization keeps its broker, policy and ledger. In v0.1 people still approve things on their approvals page; approving inside the vendor's app is planned for a later version.

Both modes share addresses, messages, permissions and ledgers, and brokers federate, so a client-mode agent is designed to work with a native one. When a provider adopts, people keep their addresses and relationships; the connector just becomes unnecessary.

## Where brokers run

The reference broker is free for any organization to use, modify and run for itself (see [Governance and licenses](#governance-and-licenses)). An organization can run it on its own servers or inside its workspace platform for the strongest control, start with its own people and no public domain document, and federate when ready. [SELF-HOST.md](../SELF-HOST.md) shows how to run one, and what isn't built yet.

## What v0.1 ships

- The specification (a draft for implementers), its JSON Schemas and conformance test vectors.
- A reference broker in TypeScript: policy enforcement on both sides, federation, an MCP connector and matching REST API with OAuth 2.1 sign-in, ledgers with receipts, and an approvals page.
- A one-command demo: one person's three agents of different trust, then two people inside one organization and across two, with a confidential field stopped before it leaves, a rogue broker refused, and matching ledgers.
- A bridge kit for client mode, with an instruction snippet for agents.

To try it, start at https://github.com/AgentLiaisonProtocol/agentliaisonprotocol:

```
git clone https://github.com/AgentLiaisonProtocol/agentliaisonprotocol alp && cd alp/reference
npm ci            # Node 22.18 or later
npm run demo      # the whole story, over real HTTP on your machine
npm test          # the test suite, including every conformance vector
```

## Built on what already exists

ALP builds on MCP and A2A rather than competing with them: MCP is the door an agent uses to reach its own person's broker, and an A2A agent can join the same way. ALP adds what those protocols leave to each deployment: which person an agent works for, proven by that person's own sign-in and domain; whether the person contacted wants to hear from this sender at all; what each person agreed to share, checked field by field outside the agent before anything leaves; and a record on each side that the other can check. Pieces of this exist elsewhere, and we cite them; we found no deployed standard that combines them for work between people, with the agents they already use.

**Could those three agents use A2A today?** Not as shipped. We found no documented way for an outside agent to reach any of them over A2A: the doors they document are connectors they call out through (MCP connectors for dots and Claude, and connectors Muse writes itself for APIs). A2A also leaves identity outside its own messages, with no notion of what a person agreed to share or of a company-versus-personal trust class. Doing it today means building a hub all three connect to, tying each agent to its person, and inventing trust classes, consent and two-sided records for it. That is what ALP standardizes: each person's home broker is that hub, on an organization's own servers or inside its workspace platform. An A2A mapping between brokers is future work.

Agents sign in to their broker with **OAuth 2.1**, and the broker signs people in through their organization's identity provider with **OpenID Connect**; the demo uses test identities. Person-to-business protocols (Poppy, PACT) and commerce protocols (AP2, ACP) complement ALP, and we intend to align with the IETF's agentproto and AIMS work.

## What's tested and what isn't

The reference broker's test suite (`npm test`) runs every conformance vector, and the specification tools check every schema and vector with an evaluator written independently of the reference broker.

**Tested with real agents together.** On November 7, 2026, we connected real agent products to the reference's development broker, with test identities, through a temporary tunnel. Claude connected as the test person Ana through a custom connector, signing in by OAuth with Claude's published client identity, and Claude Duet used the same connector, though Anthropic's documentation doesn't say it can. Muse connected as the test person Lee: it read the broker's REST description, built its own connector and took a personal access token only through its secure credential prompt. Duet sent Muse a typed availability request, and Muse saw the sender the broker had verified and replied. The broker refused a message from Muse claiming to come from Ana and a briefing request from Duet carrying a confidential amount, and held a confidential request for Lee's approvals page rather than give it to Muse, a consumer-class agent. Both ledgers verified, and all six envelopes matched across them. Duet asked before each send, and Muse before every call. Not tested: ChatGPT and dots, Grok, Gemini, Microsoft 365 Copilot, Muse through MCP, Duet's scheduled background checks, withholding a single field from a person's own personal agent, and federation between brokers. The test ran the reference broker as it was before the changes the [changelog](../CHANGELOG.md) lists under "Changed before publication"; the [bridge kit](../bridge-kit/README.md#tested-with-real-agents) has the details.

The broker's sign-in through an organization's identity provider is built and tested against a standard OIDC provider, and was tested once, on November 8, 2026, against a single-tenant Microsoft Entra ID (Free) tenant with test users: Claude on claude.ai connected through it, and the binding to tenant and object id, app roles in policy, a fresh Entra sign-in for each approval and the re-check at each token refresh (about every 10 minutes while the agent is in use) all worked; disabling a user ended their agent's connection at its next refresh, about 8 minutes later. Conditional Access, group claims, guests and multi-tenant apps weren't tried. The reference broker is new code and hasn't had an independent security review; it doesn't send email or push yet, and [KNOWN-GAPS.md](../KNOWN-GAPS.md) lists the other known gaps.

## Governance and licenses

The specification is licensed CC BY 4.0, and its schemas and conformance vectors Apache-2.0, so anyone can implement ALP without asking, including in a broker of their own that they sell. The reference broker is source-available under the [Functional Source License](../reference/LICENSE.md) (FSL-1.1-ALv2): it is free for any organization to use, modify and run for itself, but may not be made available to others in a commercial product or service that substitutes for it or offers substantially similar functionality, and each version becomes Apache-2.0 two years after it is first published. Lucaryin wrote v0.1 and is its initial steward; contributions are open, and we intend to move the specification to a neutral foundation. v0.1 is a draft and will change.

## Get involved

ALP is open to implementers and contributors:

- **Read the specification** ([spec/alp-v0.1.md](../spec/alp-v0.1.md)) and tell us where it's wrong, unclear or incomplete.
- **Run the demo and the tests** (the commands are above); the conformance vectors in `vectors/` test your own implementation too.
- **Implement it:** agent providers, workspace and collaboration platforms, agent frameworks, and organizations running their own broker.
- **Contribute and file issues** on GitHub: https://github.com/AgentLiaisonProtocol/agentliaisonprotocol/issues ([CONTRIBUTING.md](../CONTRIBUTING.md)).

Questions: hello@agentliaisonprotocol.org. Security vulnerabilities go privately to security@agentliaisonprotocol.org ([SECURITY.md](../SECURITY.md)), not to a public issue.

*ALP is an independent proposal. Naming a product or standard here describes the landscape and compatibility; it doesn't mean the maker has reviewed or endorsed ALP.*
