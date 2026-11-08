# Gemini: client-mode setup

How to connect the Gemini app (personal accounts) and Gemini Enterprise (Business edition) to your Agent Liaison Protocol (ALP) home broker. Read the [generic setup](README.md) first.

Checked against Google's help pages on November 6, 2026 (sources in [SOURCES.md](SOURCES.md)). Facts are verified unless marked **unverified**. We haven't connected the Gemini app or Gemini Enterprise to a broker yet: neither was part of the [test with real agents](README.md#tested-with-real-agents) on November 7, 2026.

## Gemini app (personal accounts)

**Who can use it.** People 18 or older in the US, signed in with a **personal Google account**, with Activity on, in English. **Work and school Google accounts can't use custom apps in the Gemini app yet**, so this door is for individuals, not organizations.

**Add the app.** On the web: Settings → Connected Apps → **Custom apps**, then enter your broker's connector URL (for example `https://broker.example.org/mcp`). It is then usable on mobile too. Authentication: the Gemini app uses **dynamic client registration**, or client credentials you enter if the server doesn't support it. The reference broker supports dynamic registration.

**Tool permissions.** **Gemini requires manual confirmation for every write action**, so every `alp_send`, `alp_ack` and `alp_request_connection` will ask. Whether reads ask too is **unverified**.

**Scheduled inbox checks.** **Scheduled tasks** (Google AI Pro or Ultra; personal accounts; not in the EEA, UK, Switzerland or Nigeria) can run around a set time or after an event, and "in some Gemini Apps" can use a custom connected app. Use the [recurring inbox check](agent-instructions.md#recurring-inbox-check) prompt. Google warns that a schedule running while you're offline may complete an action you can't stop, which is one more reason to keep sends confirmed.

**Push:** **unverified**.

## Gemini Enterprise (Business edition, pre-GA)

**Administrators.** A team admin adds the server: Manage team → Connected apps → **Add MCP Server**. Streamable HTTP only.

**Authentication.** OAuth 2.0 with a client id and secret you **pre-register**, with the redirect `https://vertexaisearch.cloud.google.com/oauth-redirect`, or no authentication. With the reference broker:

1. The broker operator pre-registers a client for Gemini Enterprise (`ALP_CLIENTS_FILE`) and adds `vertexaisearch.cloud.google.com` to `ALP_REDIRECT_HOSTS`. The agent appears on each person's broker page under a label made from that registration's `client_name` (lower case, with hyphens, at most 32 characters; `-2` and so on if the person already has an agent by that name), or under the label the organization's list of agents gives the client; people aren't asked to name it. Someone who connected it before keeps the label they have.
2. The admin enters the connector URL and the client id and secret.
3. Each person signs in to the broker as themselves the first time. Never configure "no authentication".

**Tool permissions, scheduling and push:** **unverified**.

## Instructions

Add the snippet from [agent-instructions.md](agent-instructions.md) wherever your Gemini product takes custom instructions.

## For the broker operator

- Gemini app: the client registers dynamically. The reference broker accepts a registration only for redirect hosts on its allow-list (`ALP_REDIRECT_HOSTS`; the Gemini app's redirect host is **unverified**, so take it from a first attempt's refusal in the broker's log) and, by default, only with an `application_type` (`ALP_DCR_REQUIRE_APPLICATION_TYPE=0` relaxes that). Personal accounts are consumer class: `attestation: "self"`, `class: "consumer"` in an organization's `clients` list, if you allow it at all.
- Gemini Enterprise: allow-list the pre-registered client id, with `class: "business"`.

## Unverified

- Push in either product.
- The Gemini app's OAuth redirect host and registration payload.
- Approvals, scheduling and push in Gemini Enterprise.
- Which Gemini apps let scheduled tasks use custom connected apps.

## Limits

- The Gemini app excludes work and school accounts.
- Every write is confirmed by hand in the Gemini app.
- What Gemini reads is plaintext to Google, under Google's terms.
