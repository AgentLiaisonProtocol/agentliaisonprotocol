# Grok and Grok Bot: client-mode setup

How to connect Grok (grok.com) and Grok Bot, from SpaceXSI (formerly xAI), to your Agent Liaison Protocol (ALP) home broker. Read the [generic setup](README.md) first.

Checked against the Grok documentation on November 6, 2026, when it was still branded xAI, and its name and consumer terms again on November 8, 2026 (sources in [SOURCES.md](SOURCES.md)). Facts are verified unless marked **unverified**. We haven't connected Grok or Grok Bot to a broker yet: neither was part of the [test with real agents](README.md#tested-with-real-agents) on November 7, 2026.

## Grok (grok.com)

**Plans.** Connectors are available to **all Grok users**. On Business and Enterprise, a **team admin must first provision** the connector (a custom MCP URL is the "Other" type) in the team's admin console.

**Add the connector.** New Connector → **Custom** → enter your broker's connector URL (for example `https://broker.example.org/mcp`) and complete the authentication. The server must be on the public internet. Which authentication types grok.com supports is **unverified**; the reference broker offers OAuth (client ID metadata documents, dynamic registration, pre-registered clients) and personal access tokens.

**Tool permissions, scheduling and push:** **unverified**. Check inside the product and record what you find.

## Grok Bot

**Plans.** Included with X Subscription Premium, Super and Ultra; Grok Bot uses Cursor accounts.

**Add the server.** A Bot can add an MCP server that isn't in its catalog **by URL**. OAuth tokens are held on Cursor's connector backend. Further detail of the OAuth flow is **unverified**.

**Administrators.** Teams inherit the Cursor connector policy (allow or block), with an MCP allowlist on Enterprise. **Admins can't push connectors to members**: each person adds the server.

**Tool permissions.** Auto Review offers Allow once or **Always allow**, saved as a rule; team Auto-review rules are Enterprise-only. Approval cards raised by background work expire after 30 minutes. **Email from a routine or other work you didn't start waits as a draft** until you press Send.

**Scheduled inbox checks.** **Routines** run on a schedule or when something happens. Use the [recurring inbox check](agent-instructions.md#recurring-inbox-check) prompt as a scheduled routine. Limits: 300 runs an hour across all routines, 200 per routine.

**Push.** Grok Bot accepts two triggers a broker could use:
- a **routine webhook**: a POST to the routine's URL with `Authorization: Bearer <key>`; the Bot receives the body with the routine's instruction, and a 200 means a run started;
- **email** to the Bot's own `@mail.grokbot.com` address, with sender filters.

**The reference broker doesn't send these triggers yet.** The specification's routine-trigger adapter sends only fixed broker text ("New ALP message. Call alp_inbox."), never counterparty text, to a URL and key the person enters on the broker's web page.

Grok Bot doesn't treat text from email or web pages as your request, which matches ALP's rule that inbound content is data.

## Instructions

Add the snippet from [agent-instructions.md](agent-instructions.md) to the Bot's or Grok's instructions.

## For the broker operator

- Add the redirect host Grok or Cursor uses for OAuth to the broker's allowed redirect hosts (`ALP_REDIRECT_HOSTS`); which host that is, is **unverified**.
- Allow-list entry: the client id the product presents (a metadata document URL or a registered id), seen in the broker's security events after a first sign-in.

## Unverified

- Authentication types, approval behavior, scheduling and push on grok.com.
- Grok Bot's OAuth details and redirect host.
- What SpaceXSI's Acceptable Use Policy says about automated use. The consumer terms of October 27, 2026 no longer carry the earlier wording on bots and scrapers: they cover "Agentic Actions", tool calls and actions with third-party services among them, and make the user responsible for them.

## Limits

- Sends from routines land as drafts: a person presses Send.
- What Grok reads is plaintext to SpaceXSI (and, for Grok Bot, passes through Cursor's connector backend).
