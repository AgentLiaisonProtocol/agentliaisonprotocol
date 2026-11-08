// SPDX-License-Identifier: FSL-1.1-ALv2
// Validation with the spec's own JSON Schemas (<repo>/schemas). The reference never keeps private copies,
// so it cannot drift from the spec: when a schema changes, the reference's tests show it.
// ALP_SCHEMA_DIR overrides the location.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ValidateFunction } from "ajv";
import { createAjv, toSchemaErrors } from "./ajv.ts";
import type { SchemaError } from "./ajv.ts";
import { AlpError } from "./errors.ts";
import type { ErrorCode } from "./types.ts";

export const SCHEMA_DIR = process.env["ALP_SCHEMA_DIR"] ?? fileURLToPath(new URL("../../../schemas/", import.meta.url));


/** The protocol object schemas the core validates against (file names in SCHEMA_DIR). */
export const OBJECT_SCHEMAS = {
  envelope: "envelope.schema.json",
  control: "control.schema.json",
  receipt: "receipt.schema.json",
  ratification: "ratification.schema.json",
  grant: "grant.schema.json",
  domainDocument: "domain-document.schema.json",
  jwks: "jwks.schema.json",
  orgPolicy: "org-policy.schema.json",
  ledgerEntry: "ledger-entry.schema.json",
  ledgerExport: "ledger-export.schema.json",
  securityEvent: "security-event.schema.json",
  pushEvent: "push-event.schema.json",
  scopeDefinition: "scope-definition.schema.json",
} as const;
export type ObjectKind = keyof typeof OBJECT_SCHEMAS;

/** Protocol-defined bodies for the common message types and the control messages. */
export const BODY_SCHEMAS = ["ack", "ask_human", "decline", "error", "connection_request", "connection_response", "revoke"] as const;
export type ProtocolBodyType = (typeof BODY_SCHEMAS)[number];

class SpecSchemas {
  readonly ajv = createAjv();
  private readonly validators = new Map<string, ValidateFunction>();
  /** Relative file name (`envelope.schema.json`, `messages/ack.schema.json`) → the schema's own $id. */
  private readonly ids = new Map<string, string>();

  constructor(dir: string) {
    if (!existsSync(dir)) throw new AlpError("internal", `spec schemas not found at ${dir} (set ALP_SCHEMA_DIR)`, { status: 500 });
    const files = [
      ...readdirSync(dir).filter((f) => f.endsWith(".schema.json")),
      ...(existsSync(join(dir, "messages")) ? readdirSync(join(dir, "messages")).filter((f) => f.endsWith(".schema.json")).map((f) => `messages/${f}`) : []),
    ];
    for (const f of files) {
      const schema = JSON.parse(readFileSync(join(dir, f), "utf8")) as { $id?: string };
      if (typeof schema.$id !== "string") throw new AlpError("internal", `spec schema ${f} has no $id`, { status: 500 });
      this.ids.set(f, schema.$id);
      this.ajv.addSchema(schema);
    }
  }

  validator(file: string): ValidateFunction {
    let v = this.validators.get(file);
    if (!v) {
      const id = this.ids.get(file);
      const found = id ? this.ajv.getSchema(id) : undefined;
      if (!found) throw new AlpError("internal", `spec schema ${file} is missing`, { status: 500 });
      v = found;
      this.validators.set(file, v);
    }
    return v;
  }
}

let shared: SpecSchemas | undefined;
export function specSchemas(): SpecSchemas {
  shared ??= new SpecSchemas(SCHEMA_DIR);
  return shared;
}

/** Schema errors for a protocol object ([] when valid). */
export function schemaErrors(kind: ObjectKind, value: unknown): SchemaError[] {
  const v = specSchemas().validator(OBJECT_SCHEMAS[kind]);
  return v(value) ? [] : toSchemaErrors(v.errors);
}

export function bodyErrors(type: ProtocolBodyType, value: unknown): SchemaError[] {
  const v = specSchemas().validator(`messages/${type}.schema.json`);
  return v(value) ? [] : toSchemaErrors(v.errors);
}

/** Validate or throw a AlpError with `code` naming the first problems. */
export function assertValid<T>(kind: ObjectKind, value: unknown, code: ErrorCode): T {
  const errs = schemaErrors(kind, value);
  if (errs.length) {
    throw new AlpError(code, `${kind} is invalid: ${errs.slice(0, 3).map((e) => `${e.pointer || "/"} ${e.message}`).join("; ")}`, {
      reasons: errs.slice(0, 10).map((e) => ({ code, pointer: e.pointer, detail: e.message })),
    });
  }
  return value as T;
}
