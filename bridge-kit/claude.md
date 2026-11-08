# Claude: client-mode setup

How to connect Claude (chat, Cowork and Claude Desktop) to your Agent Liaison Protocol (ALP) home broker as a custom connector. Read the [generic setup](README.md) first; this page adds what is specific to Claude.

Checked against Anthropic's documentation on November 6, 2026 (sources in [SOURCES.md](SOURCES.md)). Facts are verified unless marked **unverified**. Claude and Claude Duet were also tested on November 7, 2026, with the reference's development broker ([what the test showed](README.md#tested-with-real-agents)), and Claude (claude.ai) on November 8, 2026, with a broker that signs people in through Microsoft Entra ID ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)). Products change; check Anthropic's current help pages.

## Plans

- Custom connectors (remote MCP) work in Claude, Cowork and Claude Desktop on the **Free, Pro, Max, Ultra, Team and Enterprise** plans. **Free allows one custom connector.**
- Claude connects from **Anthropic's cloud**, so your broker's connector URL must be reachable from the public internet (Anthropic's IP ranges). A broker on a private network needs a public endpoint for its client binding.

## Administrators (Team and Enterprise)

- On Team plans, only **Owners and Primary Owners** can add a custom connector for the organization; on Enterprise, a custom role with "Manage access to Libraries" can too. Each member then **connects individually** with their own sign-in, which is what ALP needs: every member's agent signs in as that member.
- Anthropic warns that a connector set up with a shared API key gives every user that key's access. **Never use a shared credential for ALP**: each person signs in (OAuth) or uses their own personal access token.
- Claude's **Enterprise-managed authorization** (IdP-managed with Okta, or Claude-issued in beta, the option for Entra organizations) auto-connects *listed* connectors when members first log in. Whether an organization's own custom connector can use it is **unverified**, and the reference broker doesn't accept that grant yet (it is future work in the specification). Until then, a company Claude can be recorded above `vendor` only through a client your broker issues to your Claude organization alone, if Claude can present one; otherwise company and personal Claude accounts look the same to the broker.

## Add the connector

1. In Claude, open the connector settings and add a **custom connector**.
2. **URL:** your broker's connector URL, for example `https://broker.example.org/mcp`.
3. **Authentication:** "Sign in now".
4. **OAuth client:** choose **"Use Claude's published identity (Recommended)"**. Claude publishes a client ID metadata document at `https://claude.ai/oauth/mcp-oauth-client-metadata` with the callback `https://claude.ai/api/mcp/auth_callback`, and a second one at `https://claude.ai/oauth/mcp-oauth-client-metadata/confidential_client` that authenticates with Anthropic's own key (private_key_jwt). The reference broker fetches and accepts both (its preflight, November 6 and 7, 2026). In the test with real agents on November 7, 2026, Claude (claude.ai) connected this way and signed in by OAuth (Anthropic doesn't name the mechanism). On November 8, 2026, connecting to a broker that signs people in through Microsoft Entra ID, claude.ai used the first document, `https://claude.ai/oauth/mcp-oauth-client-metadata` ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)). "Register automatically" (dynamic registration) also works with the reference broker, as long as the registration carries an `application_type` or the operator has relaxed that rule.
5. Sign in on your broker's page as yourself and allow the connection. Then ask Claude to run `alp_whoami`; it should show your address.

**Fixed headers instead of OAuth.** Claude also offers **request headers** (an API key or bearer token). If your organization prefers it, create a personal access token on your broker's web page and enter it as `Authorization: Bearer <token>`. It's yours alone; revoke it on the same page.

## Tool permissions

Claude offers **"Allow always"** per tool. Anthropic's guidance is to use it only for a server and tool you trust to run unsupervised. Suggested:

- `alp_whoami`, `alp_contacts`, `alp_inbox`, `alp_thread`: Allow always (they only read).
- `alp_ack`: Allow always if you're comfortable (it changes only your own inbox).
- `alp_send`, `alp_request_connection`: ask each time, unless you have narrowed what your agent may send on your broker's page.

## Instructions

Add the snippet from [agent-instructions.md](agent-instructions.md) to your Claude project instructions or custom instructions, so Claude treats inbound content as data and sends only through `alp_send`.

## Scheduled inbox checks

**Cowork scheduled tasks** (all paid plans) run remotely on their schedule, even when your computer is asleep, and can use the connectors you've set up. Create one that runs every 30 to 60 minutes in working hours with the [recurring inbox check](agent-instructions.md#recurring-inbox-check) prompt.

## Push

None documented for custom connectors (**unverified**). Claude learns of new messages when it checks.

## Claude Duet

Duet uses the connectors you've set up in Claude and checks your accounts at set intervals; it asks before it sends a message. It is a research preview for Pro, Max and Ultra in the US (waitlist), not yet on Team or Enterprise.

**Duet used a custom connector in the test with real agents on November 7, 2026**, though Anthropic's documentation doesn't say it can: through the connector set up in Claude for the test person Ana, it called `alp_whoami` and `alp_contacts`, then sent and read messages. It asked before each send and showed times in the person's own time zone. Duet shares Claude's connection, so the broker records it as the same agent (`claude`) and can't tell Duet from Claude chat: what your organization's list of agents allows Claude, it allows Duet. **Whether Duet's background checks use custom connectors is unverified**: two calls on the same connection during the test couldn't be attributed.

## For the broker operator

- Allow-list entry (organization policy `clients`): `https://claude.ai/oauth/mcp-oauth-client-metadata`, with the scopes your organization allows and `attestation: "vendor"`. Claude's published identity is the same for every Claude account, personal ones included, so the class you give it applies to all of them: `consumer` unless you accept members' personal Claude accounts as company agents.
- **Telling the company's Claude from personal accounts.** Register a client at your broker for your Claude organization only (with a client secret), have an Owner add the connector with **"Use your own OAuth client"** and that client, and list it with `attestation: "org-client"` and `class: "enterprise"` (see the specification's Section 5.4). Whether Claude then authenticates at the token endpoint with that secret is **unverified**; the reference broker refuses the sign-in if it doesn't. Then your organization's rules can give confidential fields to the company's Claude and hold them from a personal Claude. Claude's organization-scoped sign-in assertion (Claude-issued, beta) would support `tenant`, but whether a custom connector can use it is **unverified**, and the reference broker doesn't verify it yet.
- Redirect host: `claude.ai` (allowed by default in the reference broker).
- Claude Duet uses Claude's connection, so it gets the same entry and class as Claude.
- The client binding must be publicly reachable; the person's web view must not be.

## Unverified

- Push for custom connectors.
- Whether an organization's custom connector can use Enterprise-managed authorization.
- Whether Claude Duet's background checks use custom connectors.
- Whether "Use your own OAuth client" authenticates with the client secret (needed for `org-client`).
- Which MCP revision Claude speaks today (the reference broker serves both 2026-07-28 and the 2025-11-25 handshake).

## Limits

- What Claude reads from the inbox is plaintext to Anthropic, under Anthropic's terms.
- Anthropic's consumer terms forbid driving the Claude app with automation; the broker never does. Claude calling a connector you added is the sanctioned path.
