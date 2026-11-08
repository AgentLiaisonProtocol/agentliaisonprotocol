// SPDX-License-Identifier: FSL-1.1-ALv2
import { Ajv2020 } from "ajv/dist/2020.js";
import type { ErrorObject } from "ajv";
import * as formatsNs from "ajv-formats";

type FormatsPlugin = typeof import("ajv-formats").default;
// ajv-formats is CommonJS; its default export is module.exports under Node's ESM interop.
const addFormats = (formatsNs as unknown as { default: FormatsPlugin }).default;

/**
 * A draft 2020-12 validator for the spec's schemas. Unknown keywords are errors (strictSchema), except the
 * spec's own annotation `x-alp-text`, which marks untrusted free text. Type-strictness checks are off because
 * the spec's schemas are the source of truth and use const/enum without `type`. `verbose` puts each error's parent
 * schema on it, so a refusal can list the fields allowed where an unknown one was found; Ajv then also puts the
 * checked value on each error, which nothing here ever reads or reports.
 */
export function createAjv(): Ajv2020 {
  const ajv = new Ajv2020({ strict: false, strictSchema: true, allErrors: true, validateFormats: true, verbose: true });
  addFormats(ajv);
  ajv.addKeyword({ keyword: "x-alp-text", schemaType: "string" });
  return ajv;
}

export interface SchemaError {
  /** JSON pointer into the validated value. */
  pointer: string;
  /** What is wrong there, written to follow the pointer ("/body/depth must be one of ..."); never the value itself. */
  message: string;
}

/** How refusals describe the date-time the schemas expect (RFC 3339). */
export const DATE_TIME_TEXT = "an RFC 3339 date-time in UTC with seconds, e.g. 2026-11-10T14:00:00Z";

const TYPE_TEXT: Record<string, string> = { string: "a string", integer: "an integer", number: "a number", boolean: "true or false", object: "an object", array: "an array", null: "null" };

function esc(token: string): string {
  return token.replace(/~/g, "~0").replace(/\//g, "~1");
}

function json(v: unknown): string {
  return JSON.stringify(v) ?? String(v);
}

function typeText(t: unknown): string {
  const list = Array.isArray(t) ? t.map(String) : String(t).split(",");
  return list.map((x) => TYPE_TEXT[x] ?? x).join(" or ");
}

function formatText(format: string): string {
  switch (format) {
    case "date-time":
      return `must be ${DATE_TIME_TEXT}`;
    case "date":
      return "must be a date like 2026-11-10";
    case "time":
      return "must be a time like 14:00:00Z";
    case "uri":
      return "must be an absolute URI, e.g. https://example.org/path";
    case "email":
      return "must be an email address";
    default:
      return `must be in the ${format} format`;
  }
}

/** The fields an object schema defines, in its own order. */
export function fieldsOf(schema: unknown): string[] {
  if (!schema || typeof schema !== "object") return [];
  const props = (schema as Record<string, unknown>)["properties"];
  return props && typeof props === "object" && !Array.isArray(props) ? Object.keys(props) : [];
}

const plural = (n: unknown, one: string, many: string): string => `${json(n)} ${n === 1 ? one : many}`;

/**
 * What one Ajv error says, from its keyword, its params and its schema, never from the checked value: refusal reasons
 * go to the sender's ledger, which holds pointers and rule ids, never values (spec 6.6). Null for the artifact Ajv
 * reports on an `if` whose `then` failed (the `then` error itself says what is wrong).
 */
function reasonOf(e: ErrorObject): string | null {
  const p = e.params as Record<string, unknown>;
  switch (e.keyword) {
    case "if":
      return null;
    case "required":
      return "is required and missing";
    case "additionalProperties": {
      const fields = fieldsOf(e.parentSchema);
      return fields.length ? `isn't a field here (fields: ${fields.join(", ")})` : "isn't a field here (none is defined here)";
    }
    case "enum":
      return `must be one of ${(Array.isArray(p["allowedValues"]) ? p["allowedValues"] : []).map(json).join(", ")}`;
    case "const":
      return `must be ${json(p["allowedValue"])}`;
    case "type":
      return `must be ${typeText(p["type"])}`;
    case "format":
      return formatText(String(p["format"]));
    case "minimum":
    case "exclusiveMinimum":
    case "maximum":
    case "exclusiveMaximum": {
      const cmp = String(p["comparison"]);
      const words = cmp === ">=" ? "at least" : cmp === ">" ? "greater than" : cmp === "<=" ? "at most" : "less than";
      return `must be ${words} ${json(p["limit"])}`;
    }
    case "minLength":
      return `must be at least ${plural(p["limit"], "character", "characters")} long`;
    case "maxLength":
      return `must be at most ${plural(p["limit"], "character", "characters")} long`;
    case "minItems":
      return `must have at least ${plural(p["limit"], "item", "items")}`;
    case "maxItems":
      return `must have at most ${plural(p["limit"], "item", "items")}`;
    case "minProperties":
      return `must have at least ${plural(p["limit"], "field", "fields")}`;
    case "maxProperties":
      return `must have at most ${plural(p["limit"], "field", "fields")}`;
    case "pattern":
      return `must match the pattern ${String(p["pattern"])}`;
    case "uniqueItems":
      return "must not repeat an item";
    case "multipleOf":
      return `must be a multiple of ${json(p["multipleOf"])}`;
    case "false schema":
      return "isn't allowed here";
    case "anyOf":
    case "oneOf":
      return "must match one of the allowed forms";
    case "not":
      return "isn't allowed in this form";
    case "dependentRequired":
    case "dependencies":
      return `needs ${String(p["missingProperty"])} as well`;
    default:
      return e.message ?? "is invalid";
  }
}

/**
 * Ajv's errors as one reason per pointer (several problems at one pointer are joined), in the order Ajv found them.
 * A missing or unknown field's pointer names the field itself.
 */
export function toSchemaErrors(errors: ErrorObject[] | null | undefined): SchemaError[] {
  const byPointer = new Map<string, string[]>();
  for (const e of errors ?? []) {
    const text = reasonOf(e);
    if (text === null) continue;
    let pointer = e.instancePath;
    const extra = e.params["additionalProperty"] ?? e.params["missingProperty"];
    if ((e.keyword === "additionalProperties" || e.keyword === "required") && typeof extra === "string") {
      pointer = `${pointer}/${esc(extra)}`;
    }
    const list = byPointer.get(pointer) ?? [];
    if (!list.includes(text)) list.push(text);
    byPointer.set(pointer, list);
  }
  return [...byPointer.entries()].map(([pointer, texts]) => ({ pointer, message: texts.join("; ") }));
}

/**
 * Joins sentences into one message of at most `max` characters: whole sentences while they fit, then "(and N more)"
 * for those left out. A first sentence that alone is too long is cut. `omitted` counts sentences the caller left out
 * of `parts` already (they come after them), so a caller can stop collecting once the message is full.
 */
export function joinWithin(parts: readonly string[], max: number, sep = " ", omitted = 0): string {
  let out = "";
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? "";
    const next = out ? `${out}${sep}${part}` : part;
    const left = parts.length - i - 1 + omitted;
    const tail = left > 0 ? `${sep}(and ${left} more)` : "";
    if (next.length + tail.length <= max) {
      out = next;
      continue;
    }
    // The tail accepted with the previous sentence always fits; only a too-long first sentence is cut.
    if (!out) return `${part.slice(0, Math.max(0, max - tail.length - 1))}…${tail}`.slice(0, max);
    return `${out}${sep}(and ${parts.length - i + omitted} more)`.slice(0, max);
  }
  // Every part fit, with room kept for the count of those the caller left out.
  return omitted > 0 && out ? `${out}${sep}(and ${omitted} more)` : out;
}
