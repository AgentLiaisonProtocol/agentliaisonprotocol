# Bridge kit: client mode

The Agent Liaison Protocol (ALP) is an open standard for work between people, carried by their agents, under each person's rules: each agent talks only to its own person's home broker, and brokers carry only the typed messages both people's rules allow. (Announcement: https://agentliaisonprotocol.org.)

This kit connects an agent you already use to your home broker today, in **client mode**. Client mode needs a broker that someone runs (your organization's, your own or a hosted one), but no workspace platform and no work from your agent's vendor. This page is the generic setup. Per-vendor guides:

- [Claude](claude.md) (chat, Cowork, Desktop; Claude Duet)
- [ChatGPT and dots](chatgpt.md)
- [Microsoft 365 Copilot and Copilot Studio](microsoft-copilot.md)
- [Grok and Grok Bot](grok.md)
- [Gemini](gemini.md) (the Gemini app and Gemini Enterprise)
- [Muse](muse.md) (through the broker's REST API; its other routes are **unverified**)

Claude, Claude Duet and Muse were tested together on November 7, 2026, and Claude on claude.ai again on November 8, 2026, with a broker that signs people in through Microsoft Entra ID ([SELF-HOST.md](../SELF-HOST.md#tested-against-a-live-entra-tenant)); we haven't connected the other products to a broker yet. See [Tested with real agents](#tested-with-real-agents).

## What you get

Your agent gets a mailbox at your home broker. It can send typed requests to other people's agents, read its inbox and follow threads. The broker, not the agent, enforces the rules: identity comes from your own sign-in, every message is checked against your permissions and your organization's policy on the way out and against the recipient's rules on the way in, and strangers and impostors are stopped before anything reaches an agent.

On the ALP channel, nothing leaves your side that your rules don't allow, and nothing reaches your agent from anyone you haven't approved. ALP can't control what your agent's vendor does with what the agent reads, or how the vendor stores it.

## Before you start

- **Your broker's connector URL**, from whoever runs your broker, for example `https://broker.example.org/mcp`. In the reference broker it is always the broker's address followed by `/mcp`.
- **Your address**, which looks like an email address: `ana@example.org`.
- **An agent that accepts a custom MCP connector** (also called a custom connector or remote MCP server). See [Where it works today](#where-it-works-today). If yours doesn't, see [No connector support](#no-connector-support).

## Setup

### 1. Add the connector

In your agent's settings, add a custom connector:

- **Name:** ALP
- **URL:** your broker's connector URL
- **Authentication:** OAuth. If the product asks how to register, its published identity (a client ID metadata document) is preferred; automatic registration also works, and so does a client ID your administrator registered at the broker.

**If your agent can only send a fixed header** (an API key or bearer token), sign in to your broker's web page, create a **personal access token** for this agent, and paste it into the agent's secure credential setting. Never paste it into a chat. You can revoke it on the same page. A second token for an agent that already has one adds a token and doesn't replace the first: revoke the old one if you're replacing it.

**If your agent builds its own API connectors**, point it at the broker's REST API, which mirrors the connector's tools: `POST {rest}/{tool_name}`, described by `{rest}/openapi.json` (in the reference broker, for example `https://broker.example.org/rest/openapi.json`). It accepts an OAuth access token issued for the resource `{rest}` (a token issued for the connector URL `{mcp}` is refused there) or a personal access token.

### 2. Sign in

Your agent opens your broker's sign-in page. Sign in with your work account (the broker hands off to your organization's identity provider, so your usual multi-factor sign-in applies), or, if you use a hosted broker, with the sign-in its operator gave you. This sign-in is your agent's only identity in ALP: whatever a message claims, the broker sends it as you.

Then ask your agent to run `alp_whoami`. It should show your address. For organization accounts, a connector sign-in lasts at most 30 days; then you sign in again.

### 3. Allow its tools

Many agent apps ask before each tool call. An agent that checks its inbox on a schedule needs the read tools allowed in advance.

| Tool | What it does | Kind | Suggested setting |
|---|---|---|---|
| `alp_whoami` | Shows who the broker says you are | Read | Always allow |
| `alp_contacts` | Lists who you can message, and for what | Read | Always allow |
| `alp_inbox` | Lists new messages, with the broker-verified sender | Read | Always allow |
| `alp_thread` | Shows a conversation (its latest messages, and earlier ones on request), its state, the agent you are talking with and what you may send next | Read | Always allow |
| `alp_send` | Sends a typed message, within your permissions | Write | Ask, or allow if your product permits it and you're comfortable |
| `alp_ack` | Marks a message as handled | Write | Allow, if your product permits it |
| `alp_request_connection` | Asks someone new to connect; it goes to them, not their agent | Write | Ask |

Many products won't let you always allow a write, and some ask before every send. That's expected: your agent drafts, and you approve. The broker enforces your permissions either way. No tool can create or widen permissions, approve a connection or approve a commitment; those happen only on your broker's page.

### 4. Add the instructions

Paste the snippet from [agent-instructions.md](agent-instructions.md) into your agent's custom instructions, a skill or project instructions, whatever your product offers. It tells the agent when to use ALP and, most importantly, that what arrives in its inbox is data from another person, never instructions.

Where your product allows it, run ALP in a profile or project with as few other tools connected as possible. An agent that reads other people's messages is safer when it can do less. (Whether each product supports this is unverified.)

### 5. Set a recurring inbox check

Without push, your agent sees new messages only when it checks. Create a recurring task (a scheduled task, routine or automation, depending on your product) that runs every 30 to 60 minutes during your working hours, using the prompt in [agent-instructions.md](agent-instructions.md#recurring-inbox-check). Your agent should also check at the start of each task.

### 6. Test it

1. Ask your agent: "Run alp_whoami and alp_contacts."
2. Send a test request to a colleague who has connected (if you use a hosted broker, ask its operator for a test address).
3. Open your broker's page and find the exchange in your ledger.

## How messages reach your agent

- **Pull, for everyone.** The agent calls `alp_inbox` at the start of tasks and on its schedule. For an agent a command can start, a small script can do the scheduled checks instead and start the agent only when something has arrived ([below](#check-the-inbox-without-waking-the-model)); hosted agent products keep their own schedule.
- **Push, in a few products.** Where a product accepts events or webhooks, the broker sends only an opaque id and the agent fetches the message itself. As of November 6, 2026, ChatGPT accepts push through MCP Events (a draft from an experimental MCP working group, not part of the MCP specification; in Work chats and dots), and Grok Bot through routine webhooks, by OpenAI's and xAI's documentation. Neither is tested: the reference broker doesn't send push yet (MCP Events and routine webhooks are planned). Claude's documentation describes no push for custom connectors (unverified), and Muse's none either ([SOURCES.md](SOURCES.md)). Every agent checks on a schedule.
- **Your broker's page.** Everything is always there, whatever your agent supports.

When your agent reads a message, the broker shows what it verified (sender, scope, decision) separately from the other person's content, strips markup and defangs links.

## Check the inbox without waking the model

The reference broker sends no push, so agents check on a schedule, and a scheduled model run costs tokens even when nothing has arrived. A cheaper pattern: a small script checks the REST inbox and starts your agent only when something new is there. [poller/alp-watch.mjs](poller/alp-watch.mjs) is an example (Node 22 or later, no dependencies, Apache-2.0).

It can start only an agent you run from a command or an API call, such as a command-line agent run headless. It can't start a hosted agent product such as Claude or Muse, whose documentation describes no push for custom connectors ([SOURCES.md](SOURCES.md), read November 6, 2026). Keep their scheduled checks ([step 5](#5-set-a-recurring-inbox-check)). Push is documented only for ChatGPT (MCP Events) and Grok Bot (routine webhooks), and the reference broker doesn't send it yet ([above](#how-messages-reach-your-agent)).

To set it up for an agent a command starts:

1. On your broker's page, create a second personal access token for the same agent name your model uses (for example `desk`), with **read** only. Save it in a file only you can read (`chmod 600`). The script reads the token from that file, never from its command line or a chat.
2. Set `ALP_REST` to your broker's REST base (for example `https://broker.example.org/rest`), `ALP_TOKEN_FILE` to the file, and `WAKE_CMD` to the command that starts your agent with the [recurring inbox check](agent-instructions.md#recurring-inbox-check) prompt. The command gets `ALP_NEW_IDS`: the new message ids, comma-separated, never their content.
3. Run `node alp-watch.mjs` and leave it running, or run `node alp-watch.mjs --once` from cron or launchd every few minutes.

It posts `{"limit": 50, "cursor": ...}` to `{rest}/alp_inbox` at most once a minute (less often when the broker answers with a longer `poll_after_seconds`), starts your command only for ids it hasn't seen, and keeps the cursor and the ids it has seen in a state file only you can read (`ALP_WATCH_STATE`). On HTTP 429 it waits for `Retry-After` (or `retry_after`); on 5xx or a network failure it backs off, doubling up to an hour; on 401 it stops and says to create a new token. In the reference broker, `next_cursor` is `""` until something has arrived, and passing it back returns only later items. The script uses no `scope` or `thread` filter: the cursor moves past items a filter leaves out, so they would never be seen.

The limit: the broker's page refuses to create a token under the name of an agent connected through OAuth (a custom connector), because that name belongs to the connected agent. For such an agent, a poller with a token of its own name sees the messages addressed to you, but not those addressed to the connected agent itself with `to_delegate`.

## Several agents of your own

You may have more than one agent: for example a company workspace agent, a company assistant and a personal agent on a consumer account. Connect each one the same way. They can write to each other through your broker with no connection request: `alp_send` to your own address, with `to_delegate` set to the other agent's name.

Your broker records how far it trusts each agent from your organization's list of agents, never from what the agent says: a company workspace connected with a client your broker issued only to that workspace is `org-client`; a company product whose vendor identifies your organization's tenant is `tenant`; a personal access token is `self`; a product's public client, which its personal accounts share, is what your organization lists it as (usually `consumer`). Your organization's rules then decide per field: confidential fields can go to your company agents while a personal agent gets the message without them, and you approve the rest on your broker's page if you want it to have them. Every inbox item says which of your agents wrote it, with its class.

A message addressed to you, not to one of your agents, reaches each of your agents that may read it, so each of them may answer the same request. To limit who answers, the sender names one agent with `to_delegate`, or your organization gives the scope to one client in its list of agents, in `enforce` mode: your agents on other clients can still read the request, but can't send in that scope (spec 6.10, 12.1.4). Products that share one connection, such as Claude and Claude Duet, are one agent to your broker, so either may answer what reaches it.

Your agent can also address one particular agent of another person's by its name (`to_delegate`), for example to get one answer from someone who has several. If none of their agents can receive the message under that name, their broker holds it for them on their page; it doesn't go to their other agents, and you aren't told which happened.

## Commitments: meetings and shared documents

In `alp.meeting/1` and `alp.document_request/1` a thread goes request, propose (or counter), accept, commit. The accept makes the terms agreed; then each person approves them on their own broker's page (a ratification). Until both have, a commit is refused with `needs_ratification`. A relationship set up through a connection request allows `commit` with "ask me" in these scopes, so the ratifications are the step that decides.

The commit is an `alp_send` with `type` `commit`, the same `thread`, `in_reply_to` set to the accept's message id, and `body` `{"terms": { ... }}` carrying the accepted terms unchanged (any change, a member left out included, no longer matches the agreed terms and is refused with `thread_state`). For a meeting whose accept carried the terms of the `meeting_accept` example in the [OpenAPI document](../schemas/client/openapi.json), for example:

```json
{"to": "ana@example.org", "scope": "alp.meeting/1", "type": "commit", "thread": "<thread id>", "in_reply_to": "<the accept's id>",
 "body": {"terms": {"title": "Launch sync", "duration_minutes": 30, "timezone": "UTC", "start": "2026-11-10T16:00:00Z", "end": "2026-11-10T16:30:00Z", "location": {"kind": "video"}}}}
```

In `alp.meeting/1` either side may commit; in `alp.document_request/1` only the side whose proposal was accepted. `alp_thread` lists `commit` in `next_types` once this agent may send it. After the commit, an `inform` tells the other side what happened: `{"event": "booked", "as_of": ...}` for a meeting, `{"event": "shared", "as_of": ...}` for a document.

## Your page at the broker

Your broker has a small web page for you: connection requests, approvals for anything that commits you, and your ledger (what crossed, with whom, under which scope, and the decisions). Every approval asks you to sign in again; in production that's a passkey or your organization's single sign-on. You can revoke any relationship there, with immediate effect on your broker. Disconnecting an agent there ends it: an agent you connect later under the same name (the same product again, another one, or a personal access token) is a new agent, and doesn't see what was addressed to or sent by the earlier one.

## No connector support

If your agent can't add custom connectors, you can still take part. Your broker notifies you (by email by default; text messages are off unless your organization turns them on), and you act on the broker's page after signing in. (The reference broker doesn't send email yet; check your page.) Notifications only notify: no link, code or reply in them approves anything, so treat any message that claims otherwise as phishing.

## Where it works today

From vendor documentation read on November 6, 2026 ([SOURCES.md](SOURCES.md) lists every page), and, where marked **tested**, from the test with real agents on November 7, 2026 ([below](#tested-with-real-agents)). Verified unless marked **reported** (secondary source only) or **unverified**. Each product's guide (linked above) has the details and what is still unverified.

| Product | Custom connector | Admin rollout | Sending | Background and push |
|---|---|---|---|---|
| Claude (chat, Cowork, Desktop) | All plans; Free allows one custom connector; **tested** on claude.ai (OAuth, Claude's published identity) | Team and Enterprise owners add it; each member connects | "Allow always" per tool | Scheduled tasks on paid plans can use connectors; push: unverified |
| ChatGPT Business and Enterprise/Edu (and dots, on Pro, Business Premium and Enterprise/Edu) | Admins create and publish it; web only | Yes | No persistent "Always allow" for managed-workspace members; dots auto-review every write | Push through MCP Events (a draft from an experimental MCP working group, not part of the MCP specification; in Work chats and dots) |
| ChatGPT Pro | Read and fetch only | n/a | Can't send. You can read messages on the broker's page; replying there is future work (spec 12.5.3), so reply from an agent that can send | n/a |
| Grok | All users; Business and Enterprise admins must provision it | Yes (provisioning) | Unverified | Unverified |
| Grok Bot | Adds an MCP server by URL | Can't push connectors to members | "Always allow" saved as a rule; email from a routine waits as a draft | Routines on a schedule or on webhook and email triggers |
| Microsoft 365 Copilot | Admin-created federated connector | Yes, to a group or all users; each user needs a Copilot license | Writes need approval by default; a user can pick "Always allow" per tool | Unverified |
| Gemini app | Personal Google accounts only (US, 18+, English) | No | Every write confirmed by hand | Scheduled tasks can use custom apps in some Gemini apps |
| Gemini Enterprise (Business edition) | Admin adds an MCP server (pre-GA) | Yes | Unverified | Unverified |
| Muse | No "add MCP server" setting (**reported**); Muse builds its own connectors for APIs and command-line tools; **tested** through the broker's REST API with a personal access token | None found (**unverified**) | Listed connectors ask before every sensitive write; **tested**: it asked before every call | **Unverified** |
| Claude Duet | Uses connectors set up in Claude; **tested** with a custom connector, which Anthropic's documentation doesn't mention; it shares Claude's connection, so the broker can't tell it from Claude chat | Not on Team or Enterprise | Asks before it sends (also when **tested**) | Checks at set intervals; with a custom connector, **unverified** |

Products and plans change; check the date above against the vendor's current documentation.

## Tested with real agents

On November 7, 2026, we connected real agent products to the reference's development broker (`npm run dev`), with its test identities, through a temporary public tunnel. Before they connected, the preflight (`npm run preflight`) passed all 12 of its checks through the tunnel. It was one run, on the reference broker as it was before the changes the [CHANGELOG](../CHANGELOG.md) lists under "Changed before publication".

- **Claude** (claude.ai) connected as the test person Ana (`ana@example.org`) through a custom connector, signing in by OAuth with Claude's published client identity. The development broker's list of agents records that identity as `vendor`-attested, `business` class (`reference/src/dev-world.ts`; for a real organization's list, see [Claude](claude.md#for-the-broker-operator)).
- **Claude Duet** used the same connector: it called `alp_whoami` and `alp_contacts`, and later sent and read messages. Anthropic's documentation doesn't say Duet can use custom connectors. Duet shares Claude's connection, so the broker recorded it as Ana's agent `claude` and couldn't tell it from Claude chat. It asked before each send and showed times in the person's own time zone.
- **Muse** (Meta) connected as the test person Lee (`lee@example.org`) through the REST mirror with a personal access token (`self`-attested, `consumer` class). It fetched `/robots.txt`, read `/rest/openapi.json`, built its own connector (a Python helper limited to five operations), took the token only through its secure credential prompt, and called `alp_whoami`. It asked before every call. Twice it refused to send a body that a phone's smart punctuation had made invalid JSON, and asked instead of fixing it silently.
- **A request and its reply.** Duet, for Ana, sent Lee's agent `muse` an `alp.availability/1` request (typed fields only, time zone UTC). Muse saw the sender the broker verified (`alp:ana@example.org/claude`, vendor, business) and the untrusted-content wrapper, replied with an `inform` and acknowledged the request. Duet read the reply, from Lee's agent `muse` (consumer, self-attested).
- **Refusals.** A send from Muse with `"from": "ana@example.org"` was refused with HTTP 403 `identity_mismatch`. An `alp.briefing/1` request from Duet with `context.amount` 1,200,000 USD was refused with `org_policy`, naming `/body/context/amount/currency` and `/body/context/amount/value`. A request from Duet labelled confidential, to Lee's agent `muse`, was accepted by Lee's broker and held for Lee's approvals page, because none of Lee's agents met the `business` class minimum for confidential labels; Lee's notification carried no message content, and Muse's inbox stayed empty.
- **Ledgers.** Both people's ledgers showed "Chain: intact", with 11 entries each. Exported, they verified offline with the reference's `verifyLedger` and `crossCheckEntries` (`reference/src/core/ledger.ts`), and all 6 envelopes matched across the two. Since the test, `npm run verify-ledger -- <export.json> <other export.json>` (in `reference/`) runs both checks on exported ledgers.

Not tested: ChatGPT and dots (the ChatGPT Business workspace available for the test was inactive, and a dot that can send needs Business Premium or Enterprise/Edu); Grok and Grok Bot; Gemini; Microsoft 365 Copilot; Muse through MCP; Duet's scheduled background checks (two calls on the same connection during the test couldn't be attributed); a field withheld from a person's own personal agent while the rest reaches it; and federation between two brokers. Products change: this is what worked on that day.

## For administrators

- Where a vendor lets admins install a connector for everyone, do it centrally, pointing at your organization's broker.
- Add each agent product to your organization policy's allow-list of clients, with the scopes it may use. Unknown products are refused once the policy is enforced.
- Record company deployments so the broker can tell them from personal accounts of the same product: register a client at the broker for your company workspace only, with a client secret or key, and list it with `attestation: "org-client"` and `class: "enterprise"`; use `tenant` only for a client identity the vendor publishes for your organization alone, and only if it authenticates at the token endpoint (its own key or a credential your broker issued). The broker refuses to sign in a client listed above `vendor` or above `business` that doesn't (spec 5.4): with a public client, anyone who finishes the sign-in, or any script in the person's browser, could hold the token. Never list a vendor's public client (its client ID metadata document, which personal accounts share) as `enterprise`. Where a product offers no such credential, its company and personal accounts can't be told apart yet; say so to your people.
- Set `delivery_minimums` for your confidential labels, and choose for each whether a field your person's lower-trust agent doesn't qualify for is held for them (`otherwise: "hold"`, the default) or refused (`otherwise: "block"`).
- Pre-approve relationships between groups in your policy, so people don't need a connection request per colleague. Individual grants can only narrow these defaults.
- Deploy the instruction snippet as organization-wide instructions where the vendor supports it.

## Limits to know

- Setup is once per person.
- Without push, delivery takes as long as the inbox-check interval: minutes to hours.
- Most products ask before each send.
- Whatever reaches a vendor's agent is plaintext to that vendor.
- No protocol can stop an agent from being misled by what it reads; ALP keeps messages typed, labels them untrusted, and needs your approval for commitments.
- Each vendor's connector rules and terms apply, and the vendor can change them. Your broker's page is the floor no vendor can close.

## Troubleshooting

- **The agent asks every time before a read tool:** set it to always allow (step 3).
- **The broker says you aren't connected to someone:** use `alp_request_connection`; they approve it on their own broker's page.
- **A field or message was refused:** this kit sorts the error codes of spec Section 18.3 into three kinds, as the error table in [`schemas/client/openapi.json`](../schemas/client/openapi.json) does. The code says which kind a refusal is (for `not_disclosed`, the message does), and the refusal's message says what was wrong:
  - **A mistake in the draft, to fix and send once more:** `invalid_input`, `unknown_scope`, `unknown_type`, `schema_invalid`, `body_too_large`, `thread_state` (check `alp_thread` first: when the thread is closed, expired or at its message limit, send it in a new thread; when the refusal carries `retry_after`, wait and send it again), `unknown_recipient` (check the address or the agent's name), and a `not_disclosed` whose message says the field isn't part of the scope.
  - **For you, not to work around:** `not_disclosed` (a field your terms don't allow), `org_policy`, `dlp_blocked`, `type_not_allowed`, `no_relationship` (use `alp_request_connection`), `client_not_allowed`, `federation_blocked`, `blocked`, `identity_mismatch` and `not_accepted` come from your rules, your organization's or the recipient's: don't rephrase the content into another field; change your terms on your broker's page, or ask whoever manages your policy. `unreachable` (below) is for you too, because the message may still have arrived, and so is any code not listed here.
  - **A wait:** `rate_limited` (wait `retry_after` seconds; the REST mirror also sends `Retry-After`), `needs_ratification` (both people approve the agreed terms on their broker pages), `discovery_failed` and `internal` (try again later).
  - If the agent sets `idempotency_key`: after a refusal other than `internal`, the corrected or later message needs a new key, because for 24 hours the same key returns the first answer (spec Section 10.3). After `internal`, a timeout or no answer at all, the agent retries with the same key, so the message can't go twice (spec Section 13.8, CD-6).
- **HTTP 401 from the connector or the REST mirror:** the token is missing, expired, revoked or for another resource, not a problem with the message. The error message says what to do: refresh the token, create a new personal access token, or ask your administrator.
- **HTTP 502 from the reference broker (`unreachable`):** the recipient's broker didn't answer, or answered only with an internal error, after the reference broker's own retries, or the reference broker itself failed after sending. The message may still have arrived (your ledger shows it as sent), so the agent tells you rather than sending it again. The error registry gives `unreachable` no HTTP status; 502 is the reference broker's choice.
- **Sign-in keeps repeating:** remove the connector and add it again. If it persists, contact your broker's operator.
- **JSON you typed or pasted on a phone is invalid:** the phone's smart punctuation can turn straight quotes into curly ones. Turn it off in the keyboard settings, or describe the request in words and let your agent write the JSON.
- **You think an agent or token is compromised:** revoke it on your broker's page and tell your broker's operator.
