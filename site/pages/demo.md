---
title: What the demo prints
---
# What the demo prints

`npm run demo` (in `reference/`) starts real HTTP servers on 127.0.0.1 and prints a numbered transcript. Agents from different vendors join as client-mode clients through the real OAuth flow, or with a personal access token. In steps 0 to 6 the fictional `example.org`’s people live on two hosted brokers that its domain document names, with no workspace anywhere:

0. One person’s three agents of different trust work together through his broker. A confidential field reaches the company agents but waits for the person before the personal one gets it.
1. A briefing request crosses between the two brokers.
2. A confidential financial figure is stopped before it leaves.
3. A rogue broker claiming to speak for the sender is refused, as are a token claiming another person and a replay.
4. An outsider’s message becomes a connection request to the person, never reaching their agent.
5. The recipient’s agent reads its inbox and checks the signatures against the published keys. The two agents then continue the conversation in the same thread, until one of them closes it.
6. Both ledgers point at each other.
7. The same story on `example.org`’s own broker, including a meeting both people ratify on their own approvals pages.
8. A person whose agent has no connector support approves on their approvals page, from a notification that only notifies.

The output below was captured from the CI run of commit `f05f787` on November 20, 2026 ([the run on GitHub](https://github.com/AgentLiaisonProtocol/agentliaisonprotocol/actions/runs/44823159509)). Ports and message ids differ on every run. To run it yourself, see the [quick start](/docs/quick-start/).

## The transcript

```transcript
{{include:demo-transcript.txt}}
```
