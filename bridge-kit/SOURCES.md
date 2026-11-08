# Sources for the bridge kit

Every vendor fact in the bridge kit comes from these pages, except what the bridge kit reports from the [test with real agents](README.md#tested-with-real-agents) on November 7, 2026 (in its [README](README.md), [claude.md](claude.md) and [muse.md](muse.md)). Each page was read on **November 6, 2026**, unless a date is given. Pages marked *archived* refused automated reading, so they were read from a Wayback Machine snapshot of the date shown. Pages marked *secondary* are someone else's report, used only where the guides say **reported**. Vendors change their products and pages; check the live page before relying on a detail.

## Anthropic: Claude ([claude.md](claude.md))

- Custom connectors using remote MCP (plans, the one-connector Free limit, sign-in and OAuth client options, request headers, Team and Enterprise roles, "Allow always"): https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
- Enterprise-managed authorization (IdP-managed with Okta; Claude-issued, beta): https://support.claude.com/en/articles/15537633-auto-connect-your-organization-s-apps-to-claude
- Scheduled tasks in Cowork: https://support.claude.com/en/articles/13854387-schedule-recurring-tasks-in-claude-cowork
- Claude Duet: https://support.claude.com/en/articles/17631495-get-started-with-claude-duet
- Consumer terms (automated access): https://www.anthropic.com/legal/consumer-terms
- Claude's published client ID metadata documents (read November 6 and 7, 2026): https://claude.ai/oauth/mcp-oauth-client-metadata and https://claude.ai/oauth/mcp-oauth-client-metadata/confidential_client; Claude Code's: https://claude.ai/oauth/claude-code-client-metadata

## OpenAI: ChatGPT and dots ([chatgpt.md](chatgpt.md))

- Connecting custom MCP servers in ChatGPT (plans, Pro read/fetch only, web only, frozen tool snapshot), *archived* snapshot of October 19, 2026: https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt
- Managing app permissions in ChatGPT ("Always allow" not offered to managed-workspace members), *archived* snapshot of October 10, 2026: https://help.openai.com/en/articles/20001495-managing-app-permissions-in-chatgpt
- Authentication for MCP servers (client ID metadata documents, dynamic registration, predefined clients, PKCE, `iss`, `private_key_jwt`, no custom API keys, the mTLS certificate, domain restrictions and UserInfo): https://developers.openai.com/plugins/build/auth
- MCP Events (push to Work chats and dots): https://developers.openai.com/plugins/build/mcp-events, and the experimental working group's draft: https://github.com/modelcontextprotocol/experimental-ext-triggers-events
- Apps and connectors for admins (installation settings, member permissions): https://learn.chatgpt.com/docs/enterprise/apps-and-connectors
- Plugins and third-party terms: https://learn.chatgpt.com/docs/plugins
- dots (plans, controls, tasks and memory, channels, admin guide, security): https://learn.chatgpt.com/docs/dots, https://learn.chatgpt.com/docs/dots/controls, https://learn.chatgpt.com/docs/dots/tasks-and-memory, https://learn.chatgpt.com/docs/dots/channels, https://learn.chatgpt.com/docs/enterprise/dots-admin-guide, https://learn.chatgpt.com/docs/enterprise/dots-security
- ChatGPT's published client ID metadata document and JWKS (read November 6 and 7, 2026): https://chatgpt.com/oauth/client.json and https://chatgpt.com/oauth/jwks.json

## Microsoft: Microsoft 365 Copilot and Copilot Studio ([microsoft-copilot.md](microsoft-copilot.md))

- Federated connectors overview: https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/federated-connectors-overview
- Setting up custom federated connectors (authentication options, staged rollout and deploy to all users, licenses, write approvals): https://learn.microsoft.com/en-us/microsoft-365/copilot/connectors/set-up-custom-federated-connectors
- Adding an existing MCP server to a Copilot Studio agent: https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent
- Consumer Copilot (no custom MCP door found), *secondary*: https://skillsplayground.com/integrations/microsoft-copilot/

## xAI: Grok and Grok Bot ([grok.md](grok.md))

- Grok connectors: https://docs.x.ai/grok/connectors.md and connector management for teams: https://docs.x.ai/grok/connector-management.md
- Grok Bot: https://docs.x.ai/grok-bot/overview.md, https://docs.x.ai/grok-bot/skills-routines-and-automations.md, https://docs.x.ai/grok-bot/approvals-security-and-privacy.md, https://docs.x.ai/grok-bot/computer-and-apps.md, https://docs.x.ai/grok-bot/teams-and-enterprises.md, https://docs.x.ai/x-subscription/grok-bot.md
- Terms, *secondary* (current wording unverified): https://x.ai/legal/terms-of-service

## Google: Gemini ([gemini.md](gemini.md))

- Custom apps in the Gemini app (personal accounts, US, 18+, English; write confirmation): https://support.google.com/gemini/answer/17209137
- Scheduled tasks: https://support.google.com/gemini/answer/17094507
- Gemini Enterprise, Business edition (MCP servers, pre-GA): https://support.google.com/g/answer/17106276

## Meta: Muse ([muse.md](muse.md))

- Introducing Muse for small businesses: https://about.fb.com/news/2026/09/introducing-muse-small-business/
- Security and safety for AI agents, Muse's approach (custom connectors "for other services you care about if they have their own APIs or CLIs", Sentinel): https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse
- Help Center, custom connectors and the Secure Credentials Store: https://www.meta.com/help/artificial-intelligence/1687253048996149/
- Help Center, approvals: https://www.meta.com/help/artificial-intelligence/1385290430137537/
- Muse Connector Platform (listed connectors, sensitive writes): https://platform.muse.ai/docs
- Muse Code (a different product) and MCP: https://dev.meta.ai/docs/muse-code/extending
- A third-party test of Muse building an MCP client, *secondary*: https://parallel.ai/articles/meta-muse-custom-integrations.md

## Standards cited in the guides

- MCP specification, revision 2026-07-28 (authorization, client registration, Streamable HTTP): https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP's Enterprise-Managed Authorization extension: https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
