// SPDX-License-Identifier: FSL-1.1-ALv2
// Scope registry over the spec's scope definitions (<repo>/schemas/scopes, scope-definition.schema.json).
// A scope defines body schemas for request/propose/counter/accept/inform/commit, the replies each type allows,
// a classification map (envelope-relative pointer → labels), suggested fields, and commit limits.
// ack/decline/error/ask_human bodies are protocol-defined (schemas/messages) and carry no counterparty content.

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { ValidateFunction } from "ajv";
import { toSchemaErrors } from "../ajv.ts";
import type { SchemaError } from "../ajv.ts";
import { AlpError } from "../errors.ts";
import { formatPointer, matchPattern } from "../pointers.ts";
import { SCHEMA_DIR, assertValid, bodyErrors, specSchemas } from "../spec-schemas.ts";
import { isCommonType } from "../types.ts";
import type { JsonObject, MessageType, ScopeId } from "../types.ts";

export type ScopeBodyType = "request" | "propose" | "counter" | "accept" | "inform" | "commit";

export interface ScopeDefinition {
  id: ScopeId;
  title: string;
  description: string;
  maturity: "core" | "experimental";
  starts: ("request" | "propose" | "inform")[];
  common_types: ("ack" | "decline" | "error" | "ask_human")[];
  negotiable: boolean;
  committer?: "proposer" | "either";
  types: Partial<Record<ScopeBodyType, { description: string; schema: JsonObject }>>;
  replies: Partial<Record<MessageType, MessageType[]>>;
  limits_schema?: JsonObject;
  classification: Record<string, string[]>;
  suggested?: Partial<Record<MessageType, string[]>>;
}

export interface CompiledScope {
  id: ScopeId;
  def: ScopeDefinition;
  /** Every message type the scope accepts (its own plus the common types it lists). */
  types: Set<MessageType>;
  validators: Map<MessageType, ValidateFunction>;
  /** Envelope-relative patterns of untrusted free-text strings (`x-alp-text: untrusted`), per type. */
  freeText: Map<MessageType, string[]>;
  classification: [string, string[]][];
  limits?: ValidateFunction;
}

/** The label of a leaf no classification entry names (spec 6.5). */
export const DEFAULT_LABEL = "internal";

function collectFreeText(schema: unknown, path: string[], out: string[]): void {
  if (!schema || typeof schema !== "object") return;
  const s = schema as Record<string, unknown>;
  if (s["x-alp-text"] === "untrusted") out.push(formatPointer(path));
  const props = s["properties"];
  if (props && typeof props === "object") {
    for (const [k, v] of Object.entries(props as Record<string, unknown>)) collectFreeText(v, [...path, k], out);
  }
  if (s["items"]) collectFreeText(s["items"], [...path, "*"], out);
}

export class ScopeRegistry {
  private readonly scopes = new Map<ScopeId, CompiledScope>();
  readonly source: string;

  constructor(definitions: ScopeDefinition[], source = "inline") {
    this.source = source;
    for (const d of definitions) this.register(d);
  }

  /** Load every scope in a directory (default: the spec's schemas/scopes). */
  static load(dir: string = join(SCHEMA_DIR, "scopes")): ScopeRegistry {
    const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    if (files.length === 0) throw new AlpError("internal", `no scope definitions in ${dir}`, { status: 500 });
    return new ScopeRegistry(files.map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as ScopeDefinition), dir);
  }

  /** Org scopes (`org.<domain>.<name>/<n>`) are added by the operator with register(); never fetched at message time. */
  register(input: ScopeDefinition): CompiledScope {
    const def = assertValid<ScopeDefinition>("scopeDefinition", input, "invalid_input");
    if (this.scopes.has(def.id)) throw new AlpError("invalid_input", `scope ${def.id} is defined twice`);
    const ajv = specSchemas().ajv;
    const validators = new Map<MessageType, ValidateFunction>();
    const freeText = new Map<MessageType, string[]>();
    const types = new Set<MessageType>();
    for (const [type, td] of Object.entries(def.types) as [ScopeBodyType, { schema: JsonObject }][]) {
      let v: ValidateFunction;
      try {
        v = ajv.compile(td.schema);
      } catch (err) {
        throw new AlpError("invalid_input", `scope ${def.id}/${type}: schema does not compile: ${(err as Error).message}`);
      }
      validators.set(type, v);
      const ft: string[] = [];
      collectFreeText(td.schema, ["body"], ft);
      freeText.set(type, ft);
      types.add(type);
    }
    for (const t of def.common_types) types.add(t);
    let limits: ValidateFunction | undefined;
    if (def.limits_schema) limits = ajv.compile(def.limits_schema);
    const compiled: CompiledScope = {
      id: def.id,
      def,
      types,
      validators,
      freeText,
      classification: Object.entries(def.classification),
      ...(limits ? { limits } : {}),
    };
    this.scopes.set(def.id, compiled);
    return compiled;
  }

  get(id: ScopeId): CompiledScope | undefined {
    return this.scopes.get(id);
  }

  require(id: ScopeId): CompiledScope {
    const s = this.scopes.get(id);
    if (!s) throw new AlpError("unknown_scope", `unknown scope ${id}`);
    return s;
  }

  ids(): ScopeId[] {
    return [...this.scopes.keys()].sort();
  }
}

/** Schema errors for a body ([] when valid). Pointers are envelope-relative. */
export function validateBody(scope: CompiledScope, type: MessageType, body: unknown): SchemaError[] {
  if (!scope.types.has(type)) return [{ pointer: "/type", message: `${scope.id} has no ${type}` }];
  if (isCommonType(type)) return bodyErrors(type, body).map((e) => ({ ...e, pointer: `/body${e.pointer}` }));
  const v = scope.validators.get(type);
  if (!v) return [{ pointer: "/type", message: `${scope.id} has no schema for ${type}` }];
  return v(body) ? [] : toSchemaErrors(v.errors).map((e) => ({ ...e, pointer: `/body${e.pointer}` }));
}

/**
 * Labels of a leaf (spec 6.5): the union of the labels of every entry in the scope's classification map and the
 * organization's overrides whose pattern matches the leaf or one of its ancestors. A leaf with no label is
 * `internal`; `/note` is `internal`. Sorted. `type` is kept for callers; labels don't depend on it.
 */
export function labelsOf(scope: CompiledScope, _type: MessageType, pointer: string, overrides?: Record<string, string[]>): string[] {
  if (pointer === "/note") return [DEFAULT_LABEL];
  const out = new Set<string>();
  for (const [p, ls] of scope.classification) if (matchPattern(p, pointer)) for (const l of ls) out.add(l);
  for (const [p, ls] of Object.entries(overrides ?? {})) if (matchPattern(p, pointer)) for (const l of ls) out.add(l);
  if (out.size === 0) out.add(DEFAULT_LABEL);
  return [...out].sort();
}

export function freeTextPatterns(scope: CompiledScope, type: MessageType): string[] {
  return scope.freeText.get(type) ?? [];
}

function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = row[j] ?? 0;
      row[j] = Math.min(cur + 1, (row[j - 1] ?? 0) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return row[b.length] ?? 0;
}

/** The defined field a misspelled or misremembered name most likely means: same letters, a prefix, or a small edit. */
function closestField(name: string, fields: readonly string[]): string | undefined {
  const n = name.toLowerCase();
  const lower = fields.map((f) => [f, f.toLowerCase()] as const);
  const exact = lower.find(([, f]) => f === n);
  if (exact) return exact[0];
  const prefix = lower.find(([, f]) => f.startsWith(n) || n.startsWith(f));
  if (prefix) return prefix[0];
  const inside = n.length >= 4 ? lower.find(([, f]) => f.includes(n)) : undefined;
  if (inside) return inside[0];
  let best: { field: string; d: number } | undefined;
  for (const [field, f] of lower) {
    const limit = Math.max(2, Math.floor(f.length / 3));
    // The distance is at least the difference in length: a name far longer than every field costs nothing here.
    if (Math.abs(n.length - f.length) > limit) continue;
    const d = editDistance(n, f);
    if (d <= limit && (!best || d < best.d)) best = { field, d };
  }
  return best?.field;
}

/** Where a pointer leaves a scope type's body schema: the first undefined pointer, the fields defined there, a guess. */
export interface UndefinedField {
  /** The first pointer on the way that the schema doesn't define (the pointer itself, or one of its ancestors). */
  at: string;
  /** The fields the schema defines at that level ([] when the level isn't an object). */
  fields: string[];
  suggestion?: string;
}

/**
 * Whether the scope's body schema for `type` defines an envelope-relative pointer (`/body/...`): null when it does
 * (or when it can't tell: common types and anything outside `/body`), otherwise where the pointer leaves the schema.
 * Only the schema is read, never a value.
 */
export function undefinedField(scope: CompiledScope, type: MessageType, pointer: string): UndefinedField | null {
  const schema = scope.def.types[type as ScopeBodyType]?.schema;
  if (!schema || !pointer.startsWith("/body/")) return null;
  const tokens = pointer.slice("/body/".length).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  let node: unknown = schema;
  const path = ["body"];
  for (const t of tokens) {
    const s = node && typeof node === "object" ? (node as Record<string, unknown>) : undefined;
    if (!s) return null;
    const props = s["properties"];
    if (props && typeof props === "object" && Object.prototype.hasOwnProperty.call(props, t)) {
      node = (props as Record<string, unknown>)[t];
      path.push(t);
      continue;
    }
    if (s["items"] && typeof s["items"] === "object" && (/^[0-9]+$/.test(t) || t === "*")) {
      node = s["items"];
      path.push(t);
      continue;
    }
    // An object that allows other fields defines this one too.
    if (props && s["additionalProperties"] !== false) return null;
    const fields = props && typeof props === "object" ? Object.keys(props) : [];
    const suggestion = closestField(t, fields);
    return { at: formatPointer([...path, t]), fields, ...(suggestion ? { suggestion } : {}) };
  }
  return null;
}

/** Conservative terms for a new connection: the scope's suggested fields per type; free text only where suggested. */
export function suggestedFields(scope: CompiledScope): string[] {
  const out = new Set<string>();
  for (const list of Object.values(scope.def.suggested ?? {})) for (const p of list ?? []) out.add(p);
  return [...out].sort();
}
