# ChatGPT and dots: client-mode setup

How to connect ChatGPT (chat and Work) and OpenAI's dots to your Agent Liaison Protocol (ALP) home broker as a custom MCP server. Read the [generic setup](README.md) first; this page adds what is specific to ChatGPT.

Checked against OpenAI's documentation on November 6, 2026; some help pages were read from archived copies of October 2026 because the live pages refuse automated reading (sources in [SOURCES.md](SOURCES.md)). Facts are verified unless marked **unverified**. Check OpenAI's current help pages. We haven't connected ChatGPT or a dot to a broker yet: neither was part of the [test with real agents](README.md#tested-with-real-agents) on November 7, 2026.

## Plans

| Plan | What works |
|---|---|
| **Business**, **Enterprise/Edu** | Full custom MCP servers (read and write tools), on ChatGPT **web only** |
| **Pro** | Custom MCP servers with **read/fetch permissions only**: your agent can read its ALP inbox but can't send. You can read messages on your broker's page too, but replying there is future work (spec 12.5.3), so reply from an agent that can send |
| Free, Go, Plus | Not listed for custom MCP servers (**unverified** negative) |
| **dots** | Pro 100, Pro 200 and Pro 500 (18+, outside the EEA, UK and Switzerland), Business Premium, Enterprise, Edu and Healthcare. A dot uses its owner's installed plugins under the same rules, so a Pro owner's dot is read-only too |

## Administrators

- **Business:** only admins and owners can **create and publish** a custom MCP server. **Enterprise/Edu:** admins can let roles create one (RBAC); only admins and owners publish.
- Installation settings per plugin: "Available for installation", **"Installed for workspace"**, or "Customize by role". Member permissions include "Upload plugins with custom MCP servers" and "Create plugins with MCPs".
- After an admin approves a server, ChatGPT keeps a **frozen snapshot** of its tools until an admin refreshes it. ALP's tools are fixed per protocol version, so the snapshot stays valid.
- **dots:** during the admin preview, admins enable dots per role; from **November 18, 2026**, access is on by default unless the workspace opts out.

## Add the server

1. Go to **Plugins → + → Add custom MCP server** (Developer Mode is no longer needed) and accept the risk warning.
2. **URL:** your broker's connector URL, for example `https://broker.example.org/mcp`.
3. **Authentication:** OAuth. ChatGPT registers with its **client ID metadata document** (preferred), dynamic registration, or a predefined client. ChatGPT's document is at `https://chatgpt.com/oauth/client.json`, with the callback `https://chatgpt.com/connector_platform_oauth_redirect`, and declares `private_key_jwt` with OpenAI's own key. The reference broker fetches and accepts it (preflight, November 6 and 7, 2026), and its tests complete the whole flow with a client shaped like it; a real ChatGPT hasn't connected yet (in the test of November 7, 2026, the ChatGPT Business workspace available for it was inactive, and a dot that can send needs Business Premium or Enterprise/Edu). By default ChatGPT asks only for OpenID scopes; the reference broker then grants `read` and `send` as the default scope. If your workspace restricts connector sign-ins to its email domain, the reference broker can't satisfy it yet (it offers no UserInfo endpoint and doesn't vouch for email addresses).
4. Sign in on your broker's page as yourself and allow the connection. Ask ChatGPT to run `alp_whoami`.

ChatGPT can't present custom API keys and doesn't support machine-to-machine grants, so personal access tokens don't apply here: use OAuth.

## Tool permissions

- App permissions: **Always ask**, **Allow read actions**, **Allow low-risk actions**, **Allow all actions**. "Allow read actions" covers the four read-only tools, which is enough for inbox checks.
- **"Always allow" is not offered as a persistent permission to managed-workspace members**, so sends from a workspace account will normally ask. That's expected: your agent drafts, you approve.
- **dots:** Auto-review checks every tool call labeled "write" before it runs, against your instructions, your Custom Rules and safety requirements. You can authorize a recurring action in advance (name the action, recipients, trigger and schedule), or set Custom Rules such as "Take action without asking" or "Ask before".

## Instructions

Add the snippet from [agent-instructions.md](agent-instructions.md) to your custom instructions or your dot's instructions. OpenAI's own guidance agrees: treat comments and other user-authored text as data.

## Scheduled inbox checks

- **dots** work between conversations: always-on, on schedules and by monitoring events. Give your dot the [recurring inbox check](agent-instructions.md#recurring-inbox-check) as a schedule.
- ChatGPT Work tasks and automations can also run on a schedule (which plans include them is **unverified**).

## Push

ChatGPT accepts push through **MCP Events** in Work chats on ChatGPT web, Work chats in the desktop app with Cloud selected, and dots: the server implements `events/list`, `events/subscribe` and `events/unsubscribe`, verifies a signed callback challenge, then POSTs events signed in the Standard Webhooks format. MCP Events is a **draft from an experimental MCP working group**, not part of the MCP specification.

**The reference broker doesn't offer MCP Events yet** (it is planned, carrying only an opaque id, as the specification's push section requires). Until then, ChatGPT and dots learn of new messages when they check.

## For the broker operator

- Allow-list entry: `https://chatgpt.com/oauth/client.json`, with `attestation: "vendor"`. That identity is the same for every ChatGPT account, personal ones included, and ChatGPT doesn't tell the broker which workspace a sign-in came from, so the class you give it applies to all of them: `consumer` unless you accept members' personal ChatGPT accounts as company agents.
- **Telling the company workspace from personal accounts.** The specification's `org-client` attestation (Section 5.4) is for exactly this: the workspace's connector authenticates with a credential your broker issued only to that workspace, and you list that client with `attestation: "org-client"` and `class: "enterprise"`. OpenAI documents a **predefined client** option with token endpoint authentication `none` or `private_key_jwt`. Whether a predefined client can hold a credential that only your workspace has is **unverified**: with `none` there is no credential, and with OpenAI's own signing key every workspace would share it. The reference broker refuses to record `org-client` for a client that doesn't authenticate. Until this is verified, treat ChatGPT, including dots, as one class for company and personal accounts.
- Redirect host: `chatgpt.com` (allowed by default in the reference broker).
- ChatGPT presents an OpenAI-managed mTLS client certificate (SAN `mtls.prod.connectors.openai.com`); the reference broker doesn't check it yet.
- Workspace domain restrictions in ChatGPT rely on OIDC discovery and a UserInfo `email` with `email_verified`. The reference broker reports `email_verified: false` for every person, whichever way they sign in, and serves no UserInfo, so leave domain restrictions off.

## Unverified

- Whether a predefined client lets your broker tell your company workspace from personal ChatGPT accounts (`org-client`).
- Free, Go and Plus (not listed).
- Which plans include Work tasks and automations.
- Whether ChatGPT needs a designated profile tool for this server (the tool list is fixed by the protocol; `alp_whoami` returns a stable opaque `id`).
- Which MCP revision ChatGPT speaks for this server (the reference broker serves both).

## Limits

- Pro is read-only: no sends from a Pro account's agent.
- What ChatGPT reads is plaintext to OpenAI, under OpenAI's terms; the MCP server's own terms apply to data sent through it.
- Only the owner can direct their personal dot; messages from other people don't start work. ALP content reaches a dot only as data inside its owner's own tool results.
