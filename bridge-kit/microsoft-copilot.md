# Microsoft 365 Copilot and Copilot Studio: client-mode setup

How to connect Microsoft 365 Copilot (through a federated connector) and agents built in Copilot Studio to your Agent Liaison Protocol (ALP) home broker. Read the [generic setup](README.md) first.

Checked against Microsoft Learn on November 6, 2026 (sources in [SOURCES.md](SOURCES.md)). Facts are verified unless marked **unverified**. We haven't connected Microsoft 365 Copilot or a Copilot Studio agent to a broker yet: neither was part of the [test with real agents](README.md#tested-with-real-agents) on November 7, 2026. Consumer Microsoft Copilot (copilot.microsoft.com) has **no custom MCP door** that we found (**unverified** negative).

## Microsoft 365 Copilot

**Plans and licenses.** Each user needs a **Microsoft 365 Copilot license**.

**Administrators.** A **Global Administrator or AI Administrator** creates a custom **federated connector** (MCP) in the Microsoft 365 admin center, rolls it out in stages, then **deploys it to all users** or a group. This is an organization door: people don't add it themselves.

**Authentication.** The connector supports Microsoft Entra SSO, **OAuth 2.0 with a client pre-registered in the Teams Developer Portal** (PKCE optional), or no authentication. With the reference broker, use OAuth with a pre-registered client:

1. The broker operator registers a client for Copilot at the broker (`ALP_CLIENTS_FILE`: client id, client secret, and the redirect URI Copilot uses), and adds that redirect host to `ALP_REDIRECT_HOSTS`. Which redirect URI Copilot uses is **unverified**; take it from the Teams Developer Portal registration. The agent appears on each person's broker page under a label made from that registration's `client_name` (lower case, with hyphens, at most 32 characters; `-2` and so on if the person already has an agent by that name), or under the label your organization's list of agents gives the client; people aren't asked to name it. Someone who connected it before keeps the label they have.
2. The admin enters the broker's connector URL (`https://broker.example.org/mcp`) and the client id and secret in the connector setup.
3. Each user signs in to the broker the first time Copilot calls an ALP tool. Every user signs in as themselves; never configure "no authentication".

Microsoft Entra SSO for the connector is **not supported in v0.1**: the broker accepts only tokens its own authorization server issues for its client binding (spec 5.6), never Entra-issued tokens, by design. Use OAuth with a client pre-registered at the broker.

**Tool permissions.** Write, update and delete tools default to **Needs approval**; a user can pick **Always allow** per tool and switch back. ALP's three write tools are labeled as writes, so sends ask by default.

**Scheduled inbox checks and push:** **unverified** for federated connectors. Users check the inbox by asking Copilot, or on the broker's web page.

## Copilot Studio (agents your organization builds)

- Add an MCP server (Streamable HTTP only) to an agent.
- Authentication: an **API key** (in a header or the query) or OAuth 2.0 with dynamic discovery, dynamic registration or manual client details.
- With the reference broker, use OAuth, or a **personal access token** sent as `Authorization: Bearer <token>`. Whether Copilot Studio can send the key in the `Authorization` header with the `Bearer` prefix is **unverified**; never put a token in a query string.
- Agent triggers exist; using them for a recurring inbox check wasn't re-verified.

## Instructions

Add the snippet from [agent-instructions.md](agent-instructions.md) to the agent's instructions (Copilot Studio) or to organization-wide instructions where Microsoft 365 supports them.

## For the broker operator

- Allow-list entry: the pre-registered client id you created for Copilot, with `attestation: "org-client"` (a client your broker issued only to your organization's deployment, which authenticates with its secret; see the specification's Section 5.4) and `class: "enterprise"`.
- Bind people through Entra at the broker's sign-in (issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, principals bound to `tid` + `oid`). The reference broker's Entra sign-in is built and tested against a standard OIDC provider, and was tested once against a live Entra tenant with test users, on November 8, 2026, with Claude on claude.ai as the agent, not Copilot. See [SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant).

## Unverified

- The redirect URI Copilot's federated connector uses.
- Background or scheduled use of federated connectors, and pushed events.
- (Not unverified but excluded: Entra SSO as the connector's authentication; see above.)
- Copilot Studio's API-key header format.

## Limits

- Admin-deployed and licensed: there is no self-service path.
- The Researcher agent is read-only.
- What Copilot reads is processed by Microsoft under your organization's agreement with Microsoft.
