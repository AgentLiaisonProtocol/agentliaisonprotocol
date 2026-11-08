# Muse: client-mode setup

**Status: tested once (November 7, 2026), through the broker's REST API with a personal access token.** Meta's documentation doesn't describe connecting Muse to an MCP server such as an Agent Liaison Protocol (ALP) home broker, and Muse's other routes below are still marked **unverified** or **reported**. Read the [generic setup](README.md) first.

Checked against Meta's documentation on November 6, 2026 (sources in [SOURCES.md](SOURCES.md)), and in the test with real agents on November 7, 2026 ([the whole test](README.md#tested-with-real-agents)).

## What Meta documents

- Muse is a personal agent (US and Canada) that runs on its own isolated Linux machine with sub-agents and scheduled jobs.
- **Muse can write its own custom connectors** "for other services you care about if they have their own APIs or CLIs". You ask Muse to create one; credentials go into Muse's **Secure Credentials Store**, and Meta's Sentinel inserts the real credential at the network edge, so the agent sees only a surrogate.
- Meta doesn't review custom connectors or how they use your information.
- Approvals per action type: Allow once, Allow for this task, Allow for this site, **Always allow** (for that connector) and Deny. For listed platform connectors, **sensitive writes such as sending an email ask every time** and can't be set to Always allow.
- Scheduled jobs and goals exist.

## What is reported, not documented

- A third party reports that **Muse has no "add MCP server" setting**, and that, given a server URL, Muse wrote a client with the official MCP SDK and saved it as a skill; bearer tokens fit the credential-store flow; OAuth-only services weren't tested (**reported**).

## What the test showed

On November 7, 2026, Muse connected to the reference's development broker as the test person Lee (`lee@example.org`), through the REST mirror with a personal access token; the broker recorded it as `self`-attested, `consumer` class. Muse:

1. fetched the broker's `/robots.txt` and read `/rest/openapi.json`;
2. built its own connector, a Python helper limited to five operations;
3. took the token only through its secure credential prompt;
4. called `alp_whoami`, then read a request from Ana's agent, with the sender the broker verified and inside the untrusted-content wrapper, replied with an `inform` and acknowledged the request.

It asked before every call. Twice it refused to send a body that a phone's smart punctuation had made invalid JSON, and asked instead of fixing it silently. A send from Muse with `"from": "ana@example.org"` was refused with HTTP 403 `identity_mismatch`. A request labelled confidential, addressed to Muse, was held for Lee's approvals page, because none of Lee's agents met the `business` class minimum for confidential labels, and Muse's inbox stayed empty.

## Setup

Because Muse builds its own connectors for APIs, the most direct door, and the one tested, is the broker's **REST API** with a **personal access token**:

1. Sign in to your broker's web page and create a **personal access token** labeled for Muse, with the `read` and `send` scopes. It is shown once. (An organization can turn personal access tokens off in its list of agents; then the page offers none. The broker records Muse as `self`-attested, never above `business` class, so your organization's rules treat it as a personal agent.)
2. Tell Muse to build a custom connector for your broker's REST API: `POST {rest}/{tool_name}` with a JSON body, described by `{rest}/openapi.json` (for example `https://broker.example.org/rest/openapi.json`). The tools are the same seven as the MCP connector. Ask for all seven, `alp_thread` included: an agent reads a thread with it before it replies in that thread.
3. When Muse asks for the credential, enter the token through **Muse's secure credential prompt** as a bearer token (`Authorization: Bearer <token>`). **Never paste it into the chat.**
4. Ask Muse to call `alp_whoami`. It should show your address.

**Typing JSON on a phone.** A phone's smart punctuation can turn straight quotes into curly ones, which makes JSON typed or pasted into an agent invalid. Turn smart punctuation off in the phone's keyboard settings while you do this, or describe the request in words and let Muse write the JSON.

Alternatively, give Muse the MCP connector URL (`https://broker.example.org/mcp`) with the same bearer token, as in the third-party report (**reported**; not tested).

## Tool permissions

In the test, Muse asked before every call, reads included; allow the read tools when it asks. Whether a custom-connector send can be granted "Always allow", or a perpetual Sentinel grant, is **unverified**; expect Muse to ask before each send, which is the safe default.

## Instructions

Paste the snippet from [agent-instructions.md](agent-instructions.md) into Muse's memory or instructions.

## Scheduled inbox checks

Give Muse the [recurring inbox check](agent-instructions.md#recurring-inbox-check) as a scheduled job or a goal. Whether a scheduled run can use a custom connector with no person present is **unverified**.

## Push

None for custom connectors. Some built-in connectors, such as calendars, send updates to Muse; nothing is documented for custom ones.

## For the broker operator

- Personal access tokens appear in the organization policy's `clients` list as the client id `pat`; give them `attestation: "self"` and `class: "consumer"`.
- Revoke a person's token on their web page (they can do it themselves) the moment they stop using it.

## Unverified

- Remote MCP from Muse (Meta doesn't say it is supported, and the test didn't use it).
- OAuth for Muse's custom connectors.
- Always allow for custom-connector sends.
- Scheduled runs using custom connectors unattended.
- Any organization-level administration of Muse.

## Limits

- Muse is a consumer product: no admin rollout was found.
- What Muse reads is plaintext to Meta, under Meta's terms.
