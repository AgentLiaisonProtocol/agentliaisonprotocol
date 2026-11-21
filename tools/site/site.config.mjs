// The site's single list of pages, and its constants. tools/site/README.md says how to add a page.
//
// A page entry:
//   url          the page's path from the site root ("/docs/spec/" is written as docs/spec/index.html)
//   kind         how it is made (see lib/pages.mjs): "markdown" (a repository document), "spec-published"
//                (the specification at the published commit), "page" (site/pages/*.md or *.html with front
//                matter), "guides-index", and the generated reference kinds of lib/reference-pages.mjs
//   source       the repository file it is rendered from (kinds markdown and page)
//   title        the name in navigation and in <title>
//   description  one sentence for <meta name="description">, the guides index and llms.txt; it must restate
//                what the source says (CONTRIBUTING.md "Writing style"; no new facts)
//   group        a docs group id below, or null for a page outside the docs (article layout)
//   order        position within the group (pages sort by group, then order)
//   parent       for a child page in the navigation: the parent's url
//   layout       "docs" (default for grouped pages) or "article"
//   options      kind-specific settings (see each kind)

export const site = {
  name: "Agent Liaison Protocol",
  short: "ALP",
  origin: "https://agentliaisonprotocol.org",
  repo: "https://github.com/AgentLiaisonProtocol/agentliaisonprotocol",
  branch: "main",
  versionLabel: "v0.1 draft",
  published: {
    version: "0.1.0",
    commit: "ff8d56102c29e493ec353ec6a0be5bd733b56140",
    dateText: "November 9, 2026",
  },
  security: "security@agentliaisonprotocol.org",
  ogImage: "/og-image.png",
  ogImageAlt: "Agent Liaison Protocol: between people, through their agents.",
};

// Lines the footer and the shell use. Each is the existing site's sentence, unchanged.
export const text = {
  disclaimer: "ALP is an independent proposal. Naming a product or standard here describes the landscape and compatibility; it doesn’t mean the maker has reviewed or endorsed ALP.",
  privacy: "This site sets no cookies and loads nothing from other sites.",
};

export const groups = [
  { id: "start", title: "Start" },
  { id: "specification", title: "Specification" },
  { id: "guides", title: "Guides" },
  { id: "reference", title: "Reference" },
  { id: "status", title: "Status" },
  { id: "project", title: "Project" },
];

// The top bar's links, in order.
// A link is marked current on its own page and on every page of the docs groups it names.
export const topLinks = [
  { title: "Docs", url: "/docs/", groups: ["start", "reference"] },
  { title: "Specification", url: "/docs/spec/", groups: ["specification"] },
  { title: "Guides", url: "/docs/guides/", groups: ["guides"] },
  { title: "Status", url: "/docs/status/", groups: ["status"] },
  { title: "Project", url: "/docs/project/", groups: ["project"] },
  { title: "ALP and Poppy", url: "/poppy/" },
  { title: "GitHub", href: "https://github.com/AgentLiaisonProtocol/agentliaisonprotocol" },
];

// Hand-drawn figures that replace Mermaid blocks. A Mermaid block is matched by the SHA-256 of its source,
// so when the diagram in the specification changes, the build fails until the figure is redrawn.
export const figures = [
  {
    name: "message-path",
    mermaidSha256: "534202e15f680349a63a427931b047207baab31f114946f1429ea76512b64524",
    file: "site/figures/message-path.svg",
    caption: "Redrawn from the specification’s Mermaid diagram, with the same parties, arrows and labels. Ana’s side is teal and Pat’s side is orange.",
  },
];

const SCH = "/docs/reference/schemas/";

// One page per schema file under schemas/ (except the two client files, which have the tools and REST pages).
// [file under schemas/, page slug, title, description]. The descriptions restate the specification's Appendix B
// ("Schema and vector index"); the build fails when a file under schemas/ has no page here, or a page names a
// file that doesn't exist.
const SCHEMA_FILES = [
  ["common.schema.json", "common", "Common definitions", "The schema of the shared definitions: addresses, ids, timestamps, hashes, pointers, labels, codes, decision and constraints."],
  ["control.schema.json", "control", "Control envelope", "The schema of the control envelope (JWS typ alp-control+jws)."],
  ["domain-document.schema.json", "domain-document", "Domain document", "The schema of the domain document."],
  ["envelope.schema.json", "envelope", "Envelope", "The schema of the envelope (JWS typ alp-envelope+jws)."],
  ["grant.schema.json", "grant", "Grant", "The schema of a grant."],
  ["jwks.schema.json", "jwks", "Broker JWKS", "The schema of a broker’s JWKS with alp_use."],
  ["ledger-entry.schema.json", "ledger-entry", "Ledger entry", "The schema of a ledger entry."],
  ["ledger-export.schema.json", "ledger-export", "Ledger export header", "The schema of the ledger export header."],
  ["messages/ack.schema.json", "messages/ack", "ack body", "The schema of the body of an ack message."],
  ["messages/ask_human.schema.json", "messages/ask-human", "ask_human body", "The schema of the body of an ask_human message."],
  ["messages/connection_request.schema.json", "messages/connection-request", "connection_request body", "The schema of the body of a connection_request control envelope."],
  ["messages/connection_response.schema.json", "messages/connection-response", "connection_response body", "The schema of the body of a connection_response control envelope."],
  ["messages/decline.schema.json", "messages/decline", "decline body", "The schema of the body of a decline message."],
  ["messages/error.schema.json", "messages/error", "error body", "The schema of the body of an error message."],
  ["messages/revoke.schema.json", "messages/revoke", "revoke body", "The schema of the body of a revoke control envelope."],
  ["org-policy.schema.json", "org-policy", "Organization policy", "The schema of an organization’s policy, which is private local configuration."],
  ["push-event.schema.json", "push-event", "Push event", "The schema of a push event."],
  ["ratification.schema.json", "ratification", "Ratification record", "The schema of a ratification record (JWS typ alp-ratification+jws)."],
  ["receipt.schema.json", "receipt", "Receipt", "The schema of a receipt (JWS typ alp-receipt+jws)."],
  ["scope-definition.schema.json", "scope-definition", "Scope definition", "The schema of the format a scope definition uses."],
  ["scopes/availability-1.json", "scopes/availability-1", "Scope alp.availability/1", "The definition of the core scope alp.availability/1."],
  ["scopes/briefing-1.json", "scopes/briefing-1", "Scope alp.briefing/1", "The definition of the core scope alp.briefing/1."],
  ["scopes/document_request-1.json", "scopes/document-request-1", "Scope alp.document_request/1", "The definition of the core scope alp.document_request/1."],
  ["scopes/meeting-1.json", "scopes/meeting-1", "Scope alp.meeting/1", "The definition of the core scope alp.meeting/1."],
  ["scopes/status-1.json", "scopes/status-1", "Scope alp.status/1", "The definition of the core scope alp.status/1."],
  ["security-event.schema.json", "security-event", "Security event", "The schema of a security event, which is OCSF-mapped."],
];

function schemaPages() {
  return SCHEMA_FILES.map(([file, slug, title, description], i) => ({
    url: `${SCH}${slug}/`, kind: file.startsWith("scopes/") ? "scope" : "schema", options: { file: `schemas/${file}` },
    title, group: "reference", order: 21 + i / 100, parent: SCH, description,
  }));
}

const BK = "/docs/guides/connect-an-agent/";
const RB = "/docs/guides/run-a-broker/";

export const pages = [
  // Outside the docs.
  { url: "/", kind: "page", source: "site/pages/overview.html", title: "Agent Liaison Protocol", group: null, layout: "article",
    description: "The Agent Liaison Protocol (ALP) is an open standard for work between people, carried by their agents, under each person’s rules." },
  { url: "/poppy/", kind: "page", source: "site/pages/poppy.html", title: "ALP and Poppy", group: null, layout: "article",
    description: "How the Agent Liaison Protocol fits next to Poppy (the Personal Agent Protocol): Poppy for a person’s agent and a business, ALP for work between people, and where the two meet." },
  { url: "/announcement/", kind: "markdown", source: "announcement/introducing-agent-liaison-protocol.md", title: "Introducing the Agent Liaison Protocol", group: null, layout: "article",
    options: { notice: 'This is the announcement of November 9, 2026, with its update of November 20. The <a href="/">overview</a> and the <a href="/docs/">documentation</a> are current.' },
    description: "The announcement of the Agent Liaison Protocol, published on November 9, 2026." },
  { url: "/404.html", kind: "page", source: "site/pages/404.html", title: "Page not found", group: null, layout: "article", options: { notFound: true },
    description: "There is no page at this address." },

  // Start
  { url: "/docs/", kind: "page", source: "site/pages/introduction.md", title: "Introduction", group: "start", order: 10,
    description: "What the Agent Liaison Protocol is, and where to start reading." },
  { url: "/docs/quick-start/", kind: "page", source: "site/pages/quick-start.md", title: "Quick start", group: "start", order: 20,
    description: "Three ways to start: run the demo, run a broker on one machine, or connect an agent you already use." },
  { url: "/docs/demo/", kind: "page", source: "site/pages/demo.md", title: "What the demo prints", group: "start", order: 30,
    description: "The numbered transcript the reference broker’s one-command demo prints, captured from a CI run." },
  { url: "/docs/walkthroughs/", kind: "page", source: "site/pages/walkthroughs.html", title: "Four exchanges, step by step", group: "start", order: 35,
    description: "The specification’s worked examples (Appendix A), step by step: a request in one organization, a request across two organizations’ brokers, a connection request, and ratifying a meeting." },
  { url: "/docs/other-protocols/", kind: "page", source: "site/pages/other-protocols.md", title: "ALP and other protocols", group: "start", order: 40,
    description: "How ALP relates to MCP, A2A, Poppy and other work, with pointers to the specification’s Section 17." },
  { url: "/docs/glossary/", kind: "glossary", title: "Glossary", group: "start", order: 50,
    options: { append: "site/pages/glossary-other.md" },
    description: "The terms the specification defines in its Section 2, and other terms used on this site." },

  // Specification
  { url: "/docs/spec/", kind: "markdown", source: "spec/alp-v0.1.md", title: "Specification", group: "specification", order: 10,
    options: { spec: "working" },
    description: "The Agent Liaison Protocol, version 0.1: an open standard for work between people, carried by their agents, under each person’s rules." },
  { url: "/docs/0.1/spec/", kind: "spec-published", source: "spec/alp-v0.1.md", title: "Version 0.1.0 as first published", group: "specification", order: 20,
    description: "The specification’s text as first published, version 0.1.0, dated November 9, 2026 in the changelog." },

  // Guides
  { url: "/docs/guides/", kind: "guides-index", title: "Guides", group: "guides", order: 10,
    description: "Guides for connecting an agent you already use, running a broker, and building on the reference broker." },
  { url: BK, kind: "markdown", source: "bridge-kit/README.md", title: "Connect an agent", group: "guides", order: 20,
    description: "The bridge kit connects an agent you already use to your home broker in client mode, which needs no work from the agent’s vendor." },
  { url: BK + "claude/", kind: "markdown", source: "bridge-kit/claude.md", title: "Claude", group: "guides", order: 21, parent: BK,
    description: "How to connect Claude (chat, Cowork and Claude Desktop) to an ALP home broker as a custom connector." },
  { url: BK + "chatgpt/", kind: "markdown", source: "bridge-kit/chatgpt.md", title: "ChatGPT and dots", group: "guides", order: 22, parent: BK,
    description: "How to connect ChatGPT and OpenAI’s dots to an ALP home broker as a custom MCP server." },
  { url: BK + "microsoft-copilot/", kind: "markdown", source: "bridge-kit/microsoft-copilot.md", title: "Microsoft 365 Copilot", group: "guides", order: 23, parent: BK,
    description: "How to connect Microsoft 365 Copilot and agents built in Copilot Studio to an ALP home broker." },
  { url: BK + "grok/", kind: "markdown", source: "bridge-kit/grok.md", title: "Grok and Grok Bot", group: "guides", order: 24, parent: BK,
    description: "How to connect Grok and Grok Bot to an ALP home broker." },
  { url: BK + "gemini/", kind: "markdown", source: "bridge-kit/gemini.md", title: "Gemini", group: "guides", order: 25, parent: BK,
    description: "How to connect the Gemini app and Gemini Enterprise to an ALP home broker." },
  { url: BK + "muse/", kind: "markdown", source: "bridge-kit/muse.md", title: "Muse", group: "guides", order: 26, parent: BK,
    description: "How Muse connects to an ALP home broker, tested once through the broker’s REST API with a personal access token." },
  { url: BK + "agent-instructions/", kind: "markdown", source: "bridge-kit/agent-instructions.md", title: "Agent instructions", group: "guides", order: 27, parent: BK,
    description: "Instructions to paste into your agent for working with other people’s agents through ALP, and the recurring inbox check." },
  { url: BK + "sources/", kind: "markdown", source: "bridge-kit/SOURCES.md", title: "Sources", group: "guides", order: 28, parent: BK,
    description: "The vendor pages every fact in the bridge kit comes from, and when each was read." },
  { url: RB, kind: "markdown", source: "SELF-HOST.md", title: "Run a broker", group: "guides", order: 30,
    options: { allowRawHtml: ["<your tenant>"] },
    description: "How to run the reference broker yourself, for an organization’s own people, federated with other domains, or hosted, and what isn’t built yet." },
  { url: RB + "hosted/", kind: "markdown", source: "reference/deploy/VERCEL-SUPABASE.md", title: "A hosted broker", group: "guides", order: 31, parent: RB,
    description: "How a hosted ALP broker would run on Vercel with its own Supabase project: an example for an operator; nothing has been deployed this way." },
  { url: RB + "operator-statement/", kind: "markdown", source: "reference/deploy/OPERATOR-STATEMENT.md", title: "Operator statement template", group: "guides", order: 32, parent: RB,
    description: "A starting point for the operator statement a hosted broker must publish, kept current and dated." },
  { url: "/docs/guides/reference-broker/", kind: "markdown", source: "reference/ARCHITECTURE.md", title: "Reference broker architecture", group: "guides", order: 40,
    description: "The reference broker’s module layout, its interfaces, how a message moves, and what is built and what is stubbed." },

  // Reference
  { url: "/docs/reference/", kind: "reference-index", title: "Reference", group: "reference", order: 10,
    description: "The JSON Schemas, the client tools, the REST mirror, the conformance vectors and the specification tools." },
  { url: SCH, kind: "schemas-index", title: "JSON Schemas", group: "reference", order: 20, collapse: true,
    description: "The specification’s JSON Schemas (JSON Schema 2020-12), each with its members, constraints and definitions." },
  ...schemaPages(),
  { url: "/docs/reference/tools/", kind: "tools", options: { file: "schemas/client/tools.json" }, title: "Client tools", group: "reference", order: 30,
    description: "The tools of the MCP client binding, from schemas/client/tools.json." },
  { url: "/docs/reference/rest/", kind: "rest", options: { file: "schemas/client/openapi.json" }, title: "REST mirror", group: "reference", order: 40,
    description: "The client binding’s REST mirror, from schemas/client/openapi.json." },
  { url: "/docs/reference/vectors/", kind: "vectors", source: "vectors/README.md", title: "Conformance vectors", group: "reference", order: 50,
    description: "The conformance vectors, and what each file covers." },
  { url: "/docs/reference/spec-tools/", kind: "markdown", source: "tools/spec/README.md", title: "Specification tools", group: "reference", order: 60,
    description: "Scripts that generate the conformance vectors, refresh the specification’s worked examples, and check every schema and vector with an evaluator written independently of the reference broker." },

  // Status
  { url: "/docs/status/", kind: "page", source: "site/pages/status.md", title: "Status", group: "status", order: 10,
    description: "What is tested and what is not, in ALP version 0.1, a draft for implementers, and its reference broker." },
  { url: "/docs/status/claims/", kind: "markdown", source: "CLAIMS.md", title: "Claims and evidence", group: "status", order: 20,
    description: "Each claim the README, the announcement and the bridge kit make about ALP, with the evidence for it." },
  { url: "/docs/status/known-gaps/", kind: "markdown", source: "KNOWN-GAPS.md", title: "Known gaps", group: "status", order: 30,
    description: "Known gaps in ALP v0.1 and its reference broker, listed so that implementers and operators can plan around them." },
  { url: "/docs/status/roadmap/", kind: "roadmap", title: "Roadmap", group: "status", order: 35,
    description: "What the specification’s Section 19 plans for version 0.2 or later; nothing here has a delivery date." },
  { url: "/docs/changelog/", kind: "markdown", source: "CHANGELOG.md", title: "Changelog", group: "status", order: 40,
    description: "Notable changes to the ALP specification, schemas and vectors." },

  // Project
  { url: "/docs/project/", kind: "page", source: "site/pages/project.md", title: "About the project", group: "project", order: 10,
    description: "Who wrote ALP, who stewards it, how decisions are made, and how to take part." },
  { url: "/docs/project/governance/", kind: "markdown", source: "GOVERNANCE.md", title: "Governance", group: "project", order: 20,
    description: "Who stewards ALP, the roles in the project, and how decisions are made." },
  { url: "/docs/project/contributing/", kind: "markdown", source: "CONTRIBUTING.md", title: "Contributing", group: "project", order: 30,
    description: "How to report problems, propose a change to the protocol, and contribute." },
  { url: "/docs/project/security/", kind: "markdown", source: "SECURITY.md", title: "Security policy", group: "project", order: 40,
    description: "How to report a security problem privately." },
  { url: "/docs/project/code-of-conduct/", kind: "markdown", source: "CODE_OF_CONDUCT.md", title: "Code of conduct", group: "project", order: 50,
    description: "The code of conduct everyone in the project follows." },
  { url: "/docs/project/licenses/", kind: "page", source: "site/pages/licenses.md", title: "Licenses", group: "project", order: 60,
    description: "Which license covers which part of the repository, and what each lets you do." },
];

// Notes for vector files that the README's "Files" table has no row for (vectors/README.md, "Shared fixture"
// and the sentence about keys/).
export const vectorNotes = {
  "world.json": "The shared fixture the other files refer to.",
  "keys/TEST-ONLY-private-keys.json": "TEST-ONLY private keys, published on purpose so that anyone can reproduce the signatures.",
};

// Folders of the repository served as raw files, as they are: { from, to, ext, exclude }.
export const rawFiles = [
  { from: "schemas", to: "/schemas", ext: ".json", exclude: [] },
  { from: "vectors", to: "/vectors", ext: ".json", exclude: ["vectors/keys/TEST-ONLY-private-keys.json"] },
];

// Files copied into the site as they are: { from (repository path), to (site path) }.
export const assets = [
  { from: "site/assets/og-image.png", to: "/og-image.png" },
  { from: "site/assets/favicon.svg", to: "/assets/favicon.svg" },
];

// Links in repository documents that were already broken before the site existed. Each is reported on every
// build; none may be added without a reason. { source, href, reason }
export const knownBrokenLinks = [];
