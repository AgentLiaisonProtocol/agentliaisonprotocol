// SPDX-License-Identifier: FSL-1.1-ALv2
// The normative tool list (spec 12.1.2): schemas/client/tools.json. Names, titles, descriptions, input and output
// schemas and annotations are served exactly as written and never changed at runtime, so platforms that freeze a tool
// snapshot keep working and the broker can't steer agents through its tool descriptions. The REST mirror's OpenAPI
// document (schemas/client/openapi.json) is served the same way, with {rest} filled in.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ValidateFunction } from "ajv";
import { createAjv, toSchemaErrors } from "../core/ajv.ts";
import type { SchemaError } from "../core/ajv.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { SCHEMA_DIR } from "../core/spec-schemas.ts";

export const TOOL_NAMES = ["whoami", "contacts", "send", "inbox", "thread", "ack", "request_connection"].map((n) => `${PROTOCOL.toolPrefix}${n}`);

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: { [key: string]: unknown };
  outputSchema: { [key: string]: unknown };
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
}

interface ToolsFile {
  alp: string;
  description: string;
  untrusted_notice: string;
  tools: ToolDefinition[];
}

export interface ToolCatalog {
  tools: ToolDefinition[];
  /** The fixed notice inside every untrusted-content wrapper. */
  untrustedNotice: string;
  byName: Map<string, { def: ToolDefinition; input: ValidateFunction; output: ValidateFunction }>;
  /** The OAuth scope each tool needs (spec 5.6.8): read tools need `read`, the three writes need `send`. */
  scopeFor(name: string): "read" | "send";
  validateInput(name: string, value: unknown): SchemaError[];
  validateOutput(name: string, value: unknown): SchemaError[];
  openapi(restBase: string): unknown;
}

let shared: ToolCatalog | undefined;

export function toolCatalog(): ToolCatalog {
  if (shared) return shared;
  const file = JSON.parse(readFileSync(join(SCHEMA_DIR, "client", "tools.json"), "utf8")) as ToolsFile;
  const ajv = createAjv();
  const byName = new Map<string, { def: ToolDefinition; input: ValidateFunction; output: ValidateFunction }>();
  for (const def of file.tools) {
    if (def.inputSchema["type"] !== "object" || def.outputSchema["type"] !== "object") throw new Error(`${def.name}: tool schemas must be object schemas`);
    byName.set(def.name, { def, input: ajv.compile(def.inputSchema), output: ajv.compile(def.outputSchema) });
  }
  for (const n of TOOL_NAMES) if (!byName.has(n)) throw new Error(`schemas/client/tools.json lacks ${n}`);
  const openapiRaw = readFileSync(join(SCHEMA_DIR, "client", "openapi.json"), "utf8");
  const catalog: ToolCatalog = {
    tools: file.tools,
    untrustedNotice: file.untrusted_notice,
    byName,
    scopeFor: (name) => {
      const t = byName.get(name);
      return t && t.def.annotations.readOnlyHint ? "read" : "send";
    },
    validateInput: (name, value) => {
      const t = byName.get(name);
      if (!t) return [{ pointer: "", message: "unknown tool" }];
      return t.input(value) ? [] : toSchemaErrors(t.input.errors);
    },
    validateOutput: (name, value) => {
      const t = byName.get(name);
      if (!t) return [{ pointer: "", message: "unknown tool" }];
      return t.output(value) ? [] : toSchemaErrors(t.output.errors);
    },
    openapi: (restBase) => {
      const doc = JSON.parse(openapiRaw) as { servers?: { url: string; variables?: unknown }[]; components?: { securitySchemes?: { oauth?: { flows?: { authorizationCode?: { authorizationUrl?: string; tokenUrl?: string } } } } } };
      doc.servers = [{ url: restBase }];
      const flow = doc.components?.securitySchemes?.oauth?.flows?.authorizationCode;
      if (flow) {
        const origin = new URL(restBase).origin;
        flow.authorizationUrl = `${origin}/oauth/authorize`;
        flow.tokenUrl = `${origin}/oauth/token`;
      }
      return doc;
    },
  };
  shared = catalog;
  return catalog;
}

/** The spec's shared definitions (common.schema.json $defs), to inline references for agents. */
export function commonDefs(): Record<string, unknown> {
  try {
    const s = JSON.parse(readFileSync(join(SCHEMA_DIR, "common.schema.json"), "utf8")) as { $defs?: Record<string, unknown> };
    return s.$defs ?? {};
  } catch {
    return {};
  }
}

/** Protocol-defined body schemas for the common types (ack, decline, error, ask_human), for whoami include_scopes. */
export function commonBodySchema(type: string): { [key: string]: unknown } | undefined {
  try {
    return JSON.parse(readFileSync(join(SCHEMA_DIR, "messages", `${type}.schema.json`), "utf8")) as { [key: string]: unknown };
  } catch {
    return undefined;
  }
}
