// Renders JSON Schema (draft 2020-12) as readable HTML, and keeps an account of every keyword it was given.
//
// The promise of the reference pages is that a page never silently leaves out a constraint. So rendering
// goes through one function, describe(), that handles each keyword it knows and, for any keyword it doesn't,
// records it for the page's "Other keywords" list. Every keyword of every schema node is recorded in a
// Coverage as (JSON Pointer of the node, keyword) -> where it was shown. test/reference.test.mjs walks every
// schema file with its own walker and asserts that each keyword it finds is in the Coverage.
//
// Where a keyword is shown:
//   "table"       in a properties table (a row's type, required, constraints or description) or in a list
//                 of constraints under a heading
//   "subsection"  under its own heading (a definition, or the members of a nested object)
//   "other"       in the page's "Other keywords" list (a keyword this renderer has no layout for)

import { esc } from "./html.mjs";
import { highlightJson } from "./highlight.mjs";
import { Slugger } from "./slug.mjs";

/** The JSON Pointer of a child: ptr("", "properties", "a/b") is "/properties/a~1b". */
export const ptr = (p, ...segs) => p + segs.map((s) => "/" + String(s).replace(/~/g, "~0").replace(/\//g, "~1")).join("");

// Where a schema's subschemas are (JSON Schema 2020-12 applicators).
export const SCHEMA_MAPS = ["properties", "patternProperties", "$defs", "dependentSchemas"];
export const SCHEMA_ARRAYS = ["allOf", "anyOf", "oneOf", "prefixItems"];
export const SCHEMA_SINGLE = ["items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "if", "then", "else", "not", "contains", "propertyNames", "additionalItems"];

/** Every schema node under `s` as { pointer, node }, the node itself first. */
export function* walkNodes(s, p = "") {
  yield { pointer: p, node: s };
  if (s === null || typeof s !== "object" || Array.isArray(s)) return;
  for (const k of SCHEMA_MAPS) if (s[k] && typeof s[k] === "object") for (const [n, v] of Object.entries(s[k])) yield* walkNodes(v, ptr(p, k, n));
  for (const k of SCHEMA_ARRAYS) if (Array.isArray(s[k])) for (let i = 0; i < s[k].length; i++) yield* walkNodes(s[k][i], ptr(p, k, i));
  for (const k of SCHEMA_SINGLE) if (k in s) yield* walkNodes(s[k], ptr(p, k));
}

/** The keywords of a node: its keys, or "(boolean)" for the schemas `true` and `false`. */
export function keywordsOf(node) {
  if (typeof node === "boolean") return ["(boolean)"];
  if (node === null || typeof node !== "object" || Array.isArray(node)) return ["(not a schema)"];
  return Object.keys(node);
}

export class Coverage {
  constructor() { this.map = new Map(); this.others = []; }
  cover(pointer, key, where) {
    let m = this.map.get(pointer);
    if (!m) { m = new Map(); this.map.set(pointer, m); }
    if (!m.has(key)) m.set(key, where);
  }
  has(pointer, key) { return this.map.get(pointer)?.has(key) === true; }
  /** Pointers and keywords of everything covered, as "pointer keyword" lines (for messages and tests). */
  lines() { return [...this.map].flatMap(([p, m]) => [...m.keys()].map((k) => `${p || "(root)"} ${k}`)); }
}

// ---------------------------------------------------------------------------------------------------------
// Small pieces of HTML

/** Escaped text with `code` spans turned into <code>. Nothing else in a description is markup. */
export function inlineMd(text) {
  return String(text).split(/(`[^`]+`)/).map((part, i) => (i % 2 === 1 ? `<code>${esc(part.slice(1, -1))}</code>` : esc(part))).join("");
}

const kw = (k) => `<span class="kw">${esc(k)}</span>`;
const jcode = (v) => `<code>${esc(JSON.stringify(v))}</code>`;
const tcode = (t) => `<code>${esc(t)}</code>`;
const ul = (items, cls = "cons") => (items.length ? `<ul class="${cls}">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` : "");
const typeText = (t) => (Array.isArray(t) ? t.join(" or ") : String(t));

// The order keywords are shown in. Anything not listed here is either an x- extension keyword (shown) or an
// unknown keyword (listed under "Other keywords").
const ORDER = [
  "$ref", "type", "const", "enum", "format", "pattern", "minLength", "maxLength", "minimum", "exclusiveMinimum", "maximum", "exclusiveMaximum",
  "multipleOf", "minItems", "maxItems", "uniqueItems", "contains", "minContains", "maxContains", "minProperties", "maxProperties",
  "required", "dependentRequired", "properties", "patternProperties", "additionalProperties", "unevaluatedProperties", "propertyNames",
  "items", "prefixItems", "unevaluatedItems", "additionalItems", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentSchemas",
  "default", "examples", "deprecated", "readOnly", "writeOnly", "$defs", "$schema", "$id", "$anchor", "$comment", "title", "description",
];

/**
 * The rendering context.
 *   cov            a Coverage
 *   resolveRef(ref, pointer) -> { href, label, hint } | null   (null: the build reports it and shows the text)
 *   problems       array for messages
 *   idPrefix       prefix for the ids of subsections
 *   slugger        a Slugger shared by the page so ids are unique
 *   pending        subsections queued by tables: [{ id, label, node, pointer }]
 */
/** The id of a definition's heading: "def-ulid". */
export const defAnchor = (name) => new Slugger().slug(`def-${name}`);

export function makeCtx({ resolveRef, problems, cov = new Coverage() }) {
  return { cov, resolveRef, problems, idPrefix: "", slugger: new Slugger(), pending: [] };
}

function refLink(ref, p, ctx) {
  const r = ctx.resolveRef(ref, p);
  if (!r) { ctx.problems.push(`schema ${p || "(root)"}: can't resolve $ref ${ref}`); return `${kw("$ref")} <code>${esc(ref)}</code>`; }
  return `<a href="${esc(r.href)}">${esc(r.label)}</a>${r.hint ? ` <span class="hint">${esc(r.hint)}</span>` : ""}`;
}

/** An inline sub-list for a subschema: the nested describe() as a list. */
function nested(sub, p, ctx, skip) {
  return ul(describe(sub, p, ctx, skip));
}

/**
 * The constraints of a schema node as a list of HTML strings (one per keyword or group), recording every
 * keyword in ctx.cov. `skip` names keywords the caller shows itself (and has already recorded).
 * `where` is what a keyword is recorded as ("table" by default).
 */
export function describe(n, p, ctx, skip = new Set(), where = "table") {
  if (typeof n === "boolean") {
    ctx.cov.cover(p, "(boolean)", where);
    return [n ? "any value is valid (the schema <code>true</code>)" : "no value is valid: not allowed (the schema <code>false</code>)"];
  }
  if (n === null || typeof n !== "object" || Array.isArray(n)) {
    ctx.cov.cover(p, "(not a schema)", "other");
    ctx.cov.others.push({ pointer: p, key: "(not a schema)", value: n });
    return [];
  }
  const items = [];
  const done = (k) => ctx.cov.cover(p, k, where);
  for (const k of ORDER) {
    if (!(k in n) || skip.has(k)) continue;
    const v = n[k];
    done(k);
    switch (k) {
      case "$ref": items.push(`${kw("$ref")} ${refLink(v, p, ctx)}`); break;
      case "type": items.push(`${kw("type")} ${tcode(typeText(v))}`); break;
      case "enum": items.push(`${kw("enum")} ${v.map((x) => jcode(x)).join(" ")}`); break;
      case "pattern": items.push(`${kw("pattern")} <code class="pattern">${esc(v)}</code>`); break;
      case "required": items.push(`${kw("required")} ${v.length ? v.map((x) => tcode(x)).join(" ") : "(none)"}`); break;
      case "dependentRequired":
        for (const [a, bs] of Object.entries(v)) items.push(`${kw("dependentRequired")} if ${tcode(a)} is present, ${bs.map((x) => tcode(x)).join(", ")} must be present too`);
        break;
      case "properties":
        items.push(`${kw("properties")}${ul(Object.entries(v).map(([name, sub]) => `<code class="member">${esc(name)}</code>${nested(sub, ptr(p, "properties", name), ctx)}`))}`);
        break;
      case "patternProperties":
        items.push(`${kw("patternProperties")}${ul(Object.entries(v).map(([pat, sub]) => `members whose name matches <code class="pattern">${esc(pat)}</code>${nested(sub, ptr(p, "patternProperties", pat), ctx)}`))}`);
        break;
      case "additionalProperties":
      case "unevaluatedProperties":
        if (typeof v === "boolean") ctx.cov.cover(ptr(p, k), "(boolean)", where);
        if (v === false) items.push(`${kw(k)} ${jcode(false)}: <strong>closed object</strong>, no members other than those listed`);
        else if (v === true) items.push(`${kw(k)} ${jcode(true)}: other members are allowed`);
        else items.push(`${kw(k)} every other member must match:${nested(v, ptr(p, k), ctx)}`);
        break;
      case "propertyNames": items.push(`${kw("propertyNames")} every member name must match:${nested(v, ptr(p, "propertyNames"), ctx)}`); break;
      case "items":
      case "unevaluatedItems":
      case "additionalItems": items.push(`${kw(k)} every item must match:${nested(v, ptr(p, k), ctx)}`); break;
      case "prefixItems": items.push(`${kw("prefixItems")} the first items, in order:<ol class="alts">${v.map((s, i) => `<li>${nested(s, ptr(p, "prefixItems", i), ctx)}</li>`).join("")}</ol>`); break;
      case "contains": items.push(`${kw("contains")} at least one item must match:${nested(v, ptr(p, "contains"), ctx)}`); break;
      case "allOf":
      case "anyOf":
      case "oneOf": {
        const lead = { allOf: "all of these must match", anyOf: "at least one of these must match", oneOf: "exactly one of these must match" }[k];
        items.push(`${kw(k)} ${lead}:<ol class="alts">${v.map((s, i) => `<li>${nested(s, ptr(p, k, i), ctx)}</li>`).join("")}</ol>`);
        break;
      }
      case "not": items.push(`${kw("not")} must not match:${nested(v, ptr(p, "not"), ctx)}`); break;
      case "if": items.push(`${kw("if")} when the value matches:${nested(v, ptr(p, "if"), ctx)}`); break;
      case "then": items.push(`${kw("then")} it must also match:${nested(v, ptr(p, "then"), ctx)}`); break;
      case "else": items.push(`${kw("else")} otherwise it must match:${nested(v, ptr(p, "else"), ctx)}`); break;
      case "dependentSchemas":
        items.push(`${kw("dependentSchemas")}${ul(Object.entries(v).map(([name, sub]) => `when ${tcode(name)} is present:${nested(sub, ptr(p, "dependentSchemas", name), ctx)}`))}`);
        break;
      case "$defs":
        items.push(`${kw("$defs")}${ul(Object.entries(v).map(([name, sub]) => `<code class="member">${esc(name)}</code>${nested(sub, ptr(p, "$defs", name), ctx)}`))}`);
        break;
      case "title": items.push(`<strong>${inlineMd(v)}</strong>`); break;
      case "description": items.push(`<span class="note">${inlineMd(v)}</span>`); break;
      default:
        items.push(`${kw(k)} ${jcode(v)}`);
    }
  }
  for (const k of Object.keys(n)) {
    if (ORDER.includes(k) || skip.has(k)) continue;
    if (k.startsWith("x-")) { done(k); items.push(`${kw(k)} ${jcode(n[k])} <span class="hint">extension keyword</span>`); continue; }
    ctx.cov.cover(p, k, "other");
    ctx.cov.others.push({ pointer: p, key: k, value: n[k] });
  }
  return items;
}

// ---------------------------------------------------------------------------------------------------------
// Tables of members

/** The cell text for a member's type: from `type`, a `$ref`, or what the schema is built from. Records type and $ref. */
function typeCell(n, p, ctx) {
  if (typeof n === "boolean") { ctx.cov.cover(p, "(boolean)", "table"); return n ? "any" : "not allowed"; }
  const parts = [];
  if ("$ref" in n) { ctx.cov.cover(p, "$ref", "table"); parts.push(refLink(n.$ref, p, ctx)); }
  if ("type" in n) { ctx.cov.cover(p, "type", "table"); parts.push(tcode(typeText(n.type))); }
  if (parts.length) return parts.join(" ");
  if ("const" in n) return "constant";
  if ("enum" in n) return "one of a list";
  for (const k of ["oneOf", "anyOf", "allOf"]) if (k in n) return { oneOf: "one of", anyOf: "any of", allOf: "all of" }[k];
  return "any";
}

const isObjectWithMembers = (s) => s && typeof s === "object" && !Array.isArray(s) && s.properties && typeof s.properties === "object" && !("$ref" in s);

/** The nested object a member row can show inline: the member itself, or the items of an array member. */
function inlineObjectOf(sub) {
  if (isObjectWithMembers(sub)) return { array: false };
  if (sub && typeof sub === "object" && !Array.isArray(sub.items) && isObjectWithMembers(sub.items) && sub.type === "array") return { array: true };
  return null;
}

function memberId(ctx, label) {
  return ctx.slugger.slug(`${ctx.idPrefix}members ${label}`);
}

/**
 * Rows for the `properties` of `S`. depth 0 rows are the schema's own members; depth 1 rows are the members of
 * an inline object (named "parent.member", or "parent[].member" for an array of objects). An object nested
 * deeper than that gets its own subsection ("Members of a.b.c") queued in ctx.pending.
 */
function memberRows(S, p, ctx, prefix, depth, rows) {
  const required = new Set(Array.isArray(S.required) ? S.required : []);
  for (const [name, sub] of Object.entries(S.properties)) {
    const sp = ptr(p, "properties", name);
    const label = prefix + name;
    const inl = typeof sub === "object" && sub !== null ? inlineObjectOf(sub) : null;
    const isReq = required.has(name);
    const skip = new Set(["$ref", "type", "description", "title"]);
    let extra = [];
    let childRows = null;
    if (inl && !inl.array) {
      // The member is itself an object with members.
      skip.add("properties"); skip.add("required");
      ctx.cov.cover(sp, "properties", depth === 0 ? "table" : "subsection");
      ctx.cov.cover(sp, "required", "table");
      const nodeReq = Array.isArray(sub.required) ? sub.required : [];
      const missing = nodeReq.filter((r) => !(r in sub.properties));
      if (missing.length) extra.push(`${kw("required")} ${missing.map((x) => tcode(x)).join(" ")} (not listed as members here)`);
      if (depth === 0) { childRows = []; memberRows(sub, sp, ctx, label + ".", 1, childRows); }
      else {
        const id = memberId(ctx, label);
        ctx.pending.push({ id, label, node: sub, pointer: sp });
        extra.push(`members: see <a href="#${esc(id)}">Members of <code>${esc(label)}</code></a>`);
      }
    } else if (inl && inl.array) {
      skip.add("items");
      const ip = ptr(sp, "items");
      ctx.cov.cover(sp, "items", "table");
      const itemSkip = new Set(["properties", "required", "type"]);
      ctx.cov.cover(ip, "properties", depth === 0 ? "table" : "subsection");
      ctx.cov.cover(ip, "required", "table");
      ctx.cov.cover(ip, "type", "table");
      const nodeReq = Array.isArray(sub.items.required) ? sub.items.required : [];
      const missing = nodeReq.filter((r) => !(r in sub.items.properties));
      const inner = describe(sub.items, ip, ctx, itemSkip);
      if (missing.length) inner.push(`${kw("required")} ${missing.map((x) => tcode(x)).join(" ")} (not listed as members here)`);
      if (depth === 0) {
        extra.push(`${kw("items")} every item is an object; its members are listed as ${tcode(label + "[].…")}${ul(inner)}`);
        childRows = []; memberRows(sub.items, ip, ctx, label + "[].", 1, childRows);
      } else {
        const id = memberId(ctx, label + "[]");
        ctx.pending.push({ id, label: label + "[]", node: sub.items, pointer: ip });
        extra.push(`${kw("items")} every item is an object: see <a href="#${esc(id)}">Members of <code>${esc(label + "[]")}</code></a>${ul(inner)}`);
      }
    }
    const constraints = typeof sub === "boolean" ? [] : describe(sub, sp, ctx, skip).filter(Boolean);
    const type = typeCell(sub, sp, ctx);
    let desc = sub && typeof sub === "object" && typeof sub.description === "string" ? inlineMd(sub.description) : "";
    // A member that only refers to a definition shows that definition's description.
    if (!desc && sub && typeof sub === "object" && typeof sub.$ref === "string") {
      const r = ctx.resolveRef(sub.$ref, sp);
      if (r && r.description) desc = `<span class="note">${inlineMd(r.description)}</span>`;
    }
    if (sub && typeof sub === "object" && "description" in sub) ctx.cov.cover(sp, "description", "table");
    if (sub && typeof sub === "object" && "title" in sub) ctx.cov.cover(sp, "title", "table");
    const nameHtml = prefix ? `<code class="mname"><span class="dim">${esc(prefix)}</span>${esc(name)}</code>` : `<code class="mname">${esc(name)}</code>`;
    const titleLine = sub && typeof sub === "object" && typeof sub.title === "string" ? `<strong>${inlineMd(sub.title)}</strong> ` : "";
    // Three columns: the member (its name, and "required" under it when it is), its type and constraints,
    // and its description. A long name scrolls inside its own cell; it is never broken inside a word.
    const member = `<div class="mcell">${nameHtml}</div>${isReq ? '<span class="req">required</span>' : ""}`;
    rows.push(`<tr${depth ? ' class="row-child"' : ""}><td class="m-member">${member}</td><td class="m-type"><div class="mtype">${type}</div>${ul([...extra, ...constraints])}</td><td class="m-desc">${titleLine}${desc}</td></tr>`);
    if (childRows) rows.push(...childRows);
  }
}

const TABLE_HEAD = '<thead><tr><th scope="col">Member</th><th scope="col">Type and constraints</th><th scope="col">Description</th></tr></thead>';

/** A properties table in the site's scrolling table container. */
function tableOf(rows) {
  return `<div class="table-wrap schema-table" tabindex="0" role="region" aria-label="Members">\n<table>${TABLE_HEAD}<tbody>${rows.join("")}</tbody></table>\n</div>`;
}

const heading = (level, id, inner) => `<h${level} id="${esc(id)}">${inner}<a class="anchor" href="#${esc(id)}" aria-label="Link to this section">#</a></h${level}>`;

/**
 * One schema as a block: its description, a members table when it has `properties`, and a list of every other
 * keyword it has. Nested objects deeper than one level get subsections one heading level below `level`.
 * Returns HTML. Everything under `n` is recorded in ctx.cov.
 *   skip     keywords the caller has shown (and recorded)
 *   level    the heading level for subsections (members of nested objects)
 */
export function schemaBlock(n, p, ctx, { skip = new Set(), level = 4 } = {}) {
  let out = "";
  if (typeof n === "boolean" || n === null || typeof n !== "object") {
    return ul(describe(n, p, ctx));
  }
  if (typeof n.description === "string" && !skip.has("description")) { ctx.cov.cover(p, "description", "table"); out += `<p>${inlineMd(n.description)}</p>`; }
  if (typeof n.title === "string" && !skip.has("title")) { ctx.cov.cover(p, "title", "table"); out += `<p class="schema-title"><strong>${inlineMd(n.title)}</strong></p>`; }
  const rest = new Set([...skip, "description", "title"]);
  let extra = [];
  if (n.properties && typeof n.properties === "object") {
    const rows = [];
    memberRows(n, p, ctx, "", 0, rows);
    ctx.cov.cover(p, "properties", "table");
    ctx.cov.cover(p, "required", "table");
    const missing = (Array.isArray(n.required) ? n.required : []).filter((r) => !(r in n.properties));
    if (missing.length) extra.push(`${kw("required")} ${missing.map((x) => tcode(x)).join(" ")} (not listed as members here)`);
    rest.add("properties"); rest.add("required");
    out += tableOf(rows);
  }
  const items = [...extra, ...describe(n, p, ctx, rest)];
  if (items.length) out += `<p class="rules-label">${n.properties ? "Other rules" : "Rules"}</p>${ul(items)}`;
  // Subsections for members nested deeper than one level (they may queue more).
  while (ctx.pending.length) {
    const sub = ctx.pending.shift();
    out += heading(level, sub.id, `Members of <code>${esc(sub.label)}</code>`);
    ctx.cov.cover(sub.pointer, "properties", "subsection");
    out += schemaBlock(sub.node, sub.pointer, ctx, { level });
  }
  return out;
}

/** The full schema source in a <details> block (the highlighted JSON text, exactly as in the file). */
export function sourceDetails(text, id, summary = "Full schema") {
  return `<details class="source" id="${esc(id)}"><summary>${esc(summary)}</summary><pre tabindex="0"><code class="language-json">${highlightJson(text.replace(/\n$/, ""))}</code></pre></details>`;
}

/**
 * The page body for a JSON Schema file: identity, data model, definitions, other keywords, full source.
 *   opts.servedAt   the URL where this site serves the file
 *   opts.rawPath    the repository path, for the text
 */
export function schemaPageBody(json, text, ctx, { servedAt, rawPath }) {
  const cov = ctx.cov;
  let out = "";
  // Identity.
  const idRows = [];
  if (typeof json.title === "string") { cov.cover("", "title", "table"); idRows.push(["Title", inlineMd(json.title)]); }
  if (typeof json.$id === "string") { cov.cover("", "$id", "table"); idRows.push(["<code>$id</code>", `<code class="pattern">${esc(json.$id)}</code><br><span class="hint">The <code>$id</code> names the schema. It is a <code>tag:</code> URI, not a web address.</span>`]); }
  idRows.push(["Served at", `<a href="${esc(servedAt)}">${esc(servedAt)}</a>`]);
  if (typeof json.$schema === "string") { cov.cover("", "$schema", "table"); idRows.push(["Dialect", `<code class="pattern">${esc(json.$schema)}</code> <span class="hint"><code>$schema</code></span>`]); }
  out += `<dl class="facts">${idRows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
  if (typeof json.description === "string") { cov.cover("", "description", "table"); out += `<p>${inlineMd(json.description)}</p>`; }

  // Data model.
  const hasDefs = json.$defs && typeof json.$defs === "object";
  const skipRoot = new Set(["$schema", "$id", "title", "description", "$defs"]);
  const body = schemaBlock(json, "", ctx, { skip: skipRoot, level: 3 });
  if (body) out += heading(2, "data-model", "Data model") + body;
  else if (!hasDefs) out += heading(2, "data-model", "Data model") + "<p>This schema has no members or rules of its own.</p>";

  // Definitions.
  if (hasDefs) {
    cov.cover("", "$defs", "subsection");
    out += heading(2, "definitions", "Definitions");
    out += `<p>The definitions in this file, each a subsection. Other schemas refer to them with <code>$ref</code>.</p>`;
    for (const [name, def] of Object.entries(json.$defs)) {
      const id = defAnchor(name);
      out += heading(3, id, `<code>${esc(name)}</code>`);
      ctx.idPrefix = `${name} `;
      out += schemaBlock(def, ptr("", "$defs", name), ctx, { level: 4 });
      ctx.idPrefix = "";
    }
  }
  out += otherKeywords(ctx);
  out += heading(2, "full-schema", "Full schema") + sourceDetails(text, "schema-source", `${rawPath} as published`);
  return out;
}

/** The "Other keywords" section: what the renderer has no layout for, or a sentence saying there is none. */
export function otherKeywords(ctx, label = "this schema") {
  const list = ctx.cov.others;
  if (!list.length) return heading(2, "other-keywords", "Other keywords") + `<p>None. Every keyword in ${esc(label)} is shown above.</p>`;
  return heading(2, "other-keywords", "Other keywords") + `<p>Keywords the tables above have no layout for, listed here so that none is left out.</p>${ul(list.map((o) => `<code>${esc(o.pointer || "(root)")}</code> ${kw(o.key)} ${jcode(o.value)}`))}`;
}

/**
 * Account for a whole subtree without drawing it: used where a schema is shown elsewhere (a REST body that is
 * identical to a tool's schema). Records every keyword of every node as "table" under `base`.
 */
export function coverSubtree(node, base, cov, where = "table") {
  for (const { pointer, node: n } of walkNodes(node, base)) for (const k of keywordsOf(n)) cov.cover(pointer, k, where);
}

const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
/** Structural equality of two JSON values (member order doesn't matter). */
export function deepEqual(a, b) {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}
