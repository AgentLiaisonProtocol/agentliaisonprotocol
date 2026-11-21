---
title: ALP and other protocols
---
# ALP and other protocols

| Protocol | What it connects |
|---|---|
| MCP (the Model Context Protocol) | Agents and tools |
| A2A | Agents and agents |
| Poppy (the Personal Agent Protocol) | A person’s agent and a business |
| ALP | People, through their agents, under each person’s rules |

MCP connects agents to tools. A2A connects agents to agents. ALP connects people through their agents, under each person’s rules.

## Built on what already exists

ALP builds on MCP and A2A rather than competing with them: MCP is the door an agent uses to reach its own person’s broker, and an A2A agent can join the same way. ALP adds what those protocols leave to each deployment:

- which person an agent works for, proven by that person’s own sign-in and domain;
- whether the person contacted wants to hear from this sender at all;
- what each person agreed to share, checked field by field outside the agent before anything leaves;
- a record on each side that the other can check.

Agents sign in to their broker with OAuth 2.1, and the broker signs people in through their organization’s identity provider with OpenID Connect. ALP uses MCP for its client binding and can sit beside A2A (specification Section 12.4); an A2A mapping between brokers is future work.

## Poppy

Poppy (the Personal Agent Protocol) is for a person’s agent and a business; ALP is for work between people. The specification lists conversations between a person’s agent and a business as a non-goal and leaves them to Poppy (specification Sections 1.5 and 12.6). [ALP and Poppy](/poppy/) says where the two meet, and the two rules that keep them apart.

## Other work

Person-to-business protocols and agent commerce protocols complement ALP. Pieces of what ALP does exist elsewhere: person-to-person connections whose grants are checked before the model runs, hosted connectors that let different people’s assistants message each other, peering that waits for an approval, matching records and cross-provider agent identity. What is new here, as far as we found, is the combination, not any single part: one domain-named home broker per person; disclosure enforced on both sides, field by field; ratification by both people before anything binds them; work between people across agent providers; and both client and native modes over one protocol.

Specification Section 17 names and cites each of these, with what it shares with ALP and how it differs. It cites only work that was checked against primary sources, and gives the dates. Citing a project implies no endorsement by it.
