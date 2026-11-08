// SPDX-License-Identifier: FSL-1.1-ALv2
// src/mcp: the client binding's tools (spec 12.1; schemas/client/tools.json served exactly as written), the MCP server
// over Streamable HTTP (MCP 2026-07-28 and 2025-era initialize clients on one endpoint, JSON responses), and the REST
// mirror. Tool → Broker API:
//   alp_whoami             broker.whoami + the person's usable scopes (and body schemas)   read
//   alp_contacts           the person's own terms per counterparty and scope              read
//   alp_inbox              broker.inbox, items in the untrusted-content wrapper            read
//   alp_thread             broker.thread, with ratification status and next_types         read
//   alp_send               broker.send (idempotency_key honored for 24 hours)            send
//   alp_ack                broker.ack                                                     send
//   alp_request_connection held as pending_principal until the person approves on the web view, which then
//                                  calls broker.requestConnection as the person                   send

export { ERROR_STATUS, runTool } from "./handlers.ts";
export type { ToolContext, ToolOutcome } from "./handlers.ts";
export { SERVER_INSTRUCTIONS, mcpRouter, originAllowed, sendWebResponse, toCallToolResult, toWebRequest } from "./server.ts";
export type { McpRouterOptions } from "./server.ts";
export { restRouter } from "./rest.ts";
export type { RestRouterOptions } from "./rest.ts";
export { TOOL_NAMES, commonBodySchema, commonDefs, toolCatalog } from "./tools.ts";
export type { ToolCatalog, ToolDefinition } from "./tools.ts";
export { UNTRUSTED_FOOTER, UNTRUSTED_TAG, blockJson, renderUntrusted, sanitizeBody, sanitizeFreeText } from "./render.ts";
export { PENDING_PER_DAY, PENDING_TTL_DAYS, filePending, getPending, pendingFor, settlePending } from "./pending.ts";
