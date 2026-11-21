// The generated reference pages' content: schema indexes, scope definitions, the client tools, the REST
// mirror, the vector index, the glossary and the reference index. Everything is built from the repository's
// own files (the schemas, vectors and the specification), so nothing is retyped and nothing can drift.
//
// The builders return HTML strings and record, in a Coverage (lib/schemas.mjs), every keyword they were
// given. test/reference.test.mjs checks the Coverage against an independent walk of each file.

import fs from "node:fs";
import path from "node:path";
import { esc } from "./html.mjs";
import { highlightJson } from "./highlight.mjs";
import { Slugger } from "./slug.mjs";
import { coverSubtree, deepEqual, defAnchor, inlineMd, makeCtx, otherKeywords, ptr, schemaBlock, schemaPageBody, sourceDetails } from "./schemas.mjs";
import { filesUnder, vectorCaseCount } from "./counts.mjs";

export const TAG_PREFIX = "tag:agentliaisonprotocol.org,2026-11-08:spec/0.1/";

const heading = (level, id, inner) => `<h${level} id="${esc(id)}">${inner}<a class="anchor" href="#${esc(id)}" aria-label="Link to this section">#</a></h${level}>`;
const code = (t) => `<code>${esc(t)}</code>`;
const jcode = (v) => `<code>${esc(JSON.stringify(v))}</code>`;
const ul = (items, cls = "cons") => (items.length ? `<ul class="${cls}">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` : "");
const wrapTable = (inner, label, cls = "") => `<div class="table-wrap${cls ? " " + cls : ""}" tabindex="0" role="region" aria-label="${esc(label)}">\n<table>${inner}</table>\n</div>`;
const facts = (rows) => `<dl class="facts">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;

/** Read every JSON file under schemas/ (text and parsed). */
export function loadSchemaFiles(root) {
  return filesUnder(root, "schemas").filter((f) => f.endsWith(".json")).map((rel) => {
    const text = fs.readFileSync(path.join(root, rel), "utf8");
    return { rel, text, json: JSON.parse(text) };
  });
}

/** The rows of Appendix B of the specification: [{ files: "`schemas/…`", defines }] for the schema rows. */
export function appendixBRows(specMd) {
  const start = specMd.indexOf("\n## Appendix B.");
  if (start === -1) throw new Error("spec/alp-v0.1.md: no Appendix B");
  const end = specMd.indexOf("\n---", start);
  const rows = [];
  for (const m of specMd.slice(start, end === -1 ? undefined : end).matchAll(/^\| (`[^|]+`(?:, `[^|]+`)*) \| ([^|]+) \|$/gm)) {
    rows.push({ cell: m[1], files: [...m[1].matchAll(/`([^`]+)`/g)].map((x) => x[1]), defines: m[2].trim() });
  }
  return rows;
}

/** The Appendix B row that describes a repository file (exact, or by a `*` pattern). */
export function appendixRowFor(rows, rel) {
  const exact = rows.find((r) => r.files.includes(rel));
  if (exact) return exact;
  return rows.find((r) => r.files.some((f) => f.includes("*") && new RegExp("^" + f.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*") + "$").test(rel))) || null;
}

/** A resolver for $ref values: tag: URIs of the schema files, and local #/$defs/… references. */
export function makeResolver({ files, pageUrlFor, currentFile, link }) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  return (ref) => {
    const hash = ref.indexOf("#");
    const base = hash === -1 ? ref : ref.slice(0, hash);
    const frag = hash === -1 ? "" : ref.slice(hash + 1);
    let rel = currentFile;
    if (base) {
      if (!base.startsWith(TAG_PREFIX)) return null;
      rel = base.slice(TAG_PREFIX.length);
    }
    const target = byRel.get(rel);
    const url = target && pageUrlFor(rel);
    if (!target || !url) return null;
    if (frag === "") return { href: link(url), label: rel.replace(/^schemas\//, "").replace(/\.schema\.json$/, "").replace(/\.json$/, "") };
    const m = /^\/\$defs\/([^/]+)$/.exec(frag);
    if (!m) return null;
    const def = target.json.$defs?.[m[1]];
    if (def === undefined) return null;
    let hint = "";
    if (def && typeof def === "object") {
      if ("type" in def) hint = Array.isArray(def.type) ? def.type.join(" or ") : String(def.type);
      else if ("enum" in def) hint = "one of a list";
      else if ("const" in def) hint = "constant";
      else if ("$ref" in def) hint = "";
    }
    return { href: link(url + "#" + defAnchor(m[1])), label: m[1], hint, description: def && typeof def === "object" && typeof def.description === "string" ? def.description : "" };
  };
}

// ---------------------------------------------------------------------------------------------------------
// A JSON Schema file

export function schemaPage({ file, resolveRef, servedAt }) {
  const problems = [];
  const ctx = makeCtx({ resolveRef, problems });
  const body = schemaPageBody(file.json, file.text, ctx, { servedAt, rawPath: file.rel });
  return { body, cov: ctx.cov, problems, outline: outlineOf(body) };
}

/** [{ depth, id, text }] for the h2 and h3 headings of generated HTML. */
export function outlineOf(html) {
  const out = [];
  for (const m of html.matchAll(/<h([23]) id="([^"]+)">([\s\S]*?)<a class="anchor"/g)) out.push({ depth: Number(m[1]), id: m[2], text: m[3].replace(/<[^>]*>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'") });
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// A scope definition (schemas/scopes/*.json): the file format is the one of schemas/scope-definition.schema.json

const SCOPE_FACT_KEYS = ["id", "title", "maturity", "negotiable", "committer", "starts", "common_types"];
const CODE_LIST = (a) => a.map((x) => code(x)).join(" ");

export function scopePage({ file, resolveRef, servedAt, link }) {
  const problems = [];
  const ctx = makeCtx({ resolveRef, problems });
  const cov = ctx.cov;
  const j = file.json;
  const handled = new Set();
  const take = (k, where = "table") => { handled.add(k); cov.cover("", k, where); };
  let out = "";

  const rows = [];
  for (const k of SCOPE_FACT_KEYS) {
    if (!(k in j)) continue;
    take(k);
    const v = j[k];
    rows.push([code(k), Array.isArray(v) ? CODE_LIST(v) : typeof v === "string" ? (k === "title" ? inlineMd(v) : code(v)) : jcode(v)]);
  }
  rows.push(["Served at", `<a href="${esc(servedAt)}">${esc(servedAt)}</a>`]);
  out += facts(rows);
  if ("description" in j) { take("description"); out += `<p>${inlineMd(j.description)}</p>`; }
  out += `<p class="hint-p">This file is a scope definition, the format of <a href="${esc(link("/docs/reference/schemas/scope-definition/"))}"><code>scope-definition.schema.json</code></a>. In a body schema, <code>"x-alp-text": "untrusted"</code> marks a free-text string (specification Sections <a href="${esc(link("/docs/spec/#65-pointer-patterns-coverage-and-classification"))}">6.5</a> and <a href="${esc(link("/docs/spec/#73-body-schema-rules"))}">7.3</a>).</p>`;

  // Message types, each with its body schema.
  if (j.types && typeof j.types === "object") {
    take("types", "subsection");
    out += heading(2, "message-types", "Message types");
    out += "<p>The body schema of each message type this scope defines. The protocol-defined types listed under <code>common_types</code> (<code>ack</code>, <code>decline</code>, <code>error</code> and <code>ask_human</code>) have their own schemas.</p>";
    for (const [t, def] of Object.entries(j.types)) {
      const tp = ptr("", "types", t);
      const id = ctx.slugger.slug(`type-${t}`);
      out += heading(3, id, `<code>${esc(t)}</code>`);
      if (def && typeof def === "object") {
        if ("description" in def) { cov.cover(tp, "description", "table"); out += `<p>${inlineMd(def.description)}</p>`; }
        if ("schema" in def) {
          cov.cover(tp, "schema", "subsection");
          ctx.idPrefix = `${t} `;
          out += schemaBlock(def.schema, ptr(tp, "schema"), ctx, { level: 4 });
          ctx.idPrefix = "";
        }
        for (const k of Object.keys(def)) if (k !== "description" && k !== "schema") { cov.cover(tp, k, "other"); cov.others.push({ pointer: tp, key: k, value: def[k] }); }
      }
    }
  }
  if (j.replies && typeof j.replies === "object") {
    take("replies");
    out += heading(2, "replies", "Replies");
    out += "<p>Which message types may answer each type.</p>";
    out += wrapTable(`<thead><tr><th>A message of type</th><th>may be answered with</th></tr></thead><tbody>${Object.entries(j.replies).map(([t, a]) => `<tr><td>${code(t)}</td><td>${CODE_LIST(a)}</td></tr>`).join("")}</tbody>`, "Replies");
  }
  if (j.limits_schema !== undefined) {
    take("limits_schema", "subsection");
    out += heading(2, "limits-schema", "Limits schema");
    out += "<p>The schema of the limits this scope's negotiation keeps to.</p>";
    ctx.idPrefix = "limits ";
    out += schemaBlock(j.limits_schema, "/limits_schema", ctx, { level: 3 });
    ctx.idPrefix = "";
  }
  if (j.classification && typeof j.classification === "object") {
    take("classification");
    out += heading(2, "classification", "Classification");
    out += "<p>The classification labels of each field, by JSON Pointer.</p>";
    out += wrapTable(`<thead><tr><th>Pointer</th><th>Labels</th></tr></thead><tbody>${Object.entries(j.classification).map(([pt, a]) => `<tr><td>${code(pt)}</td><td>${CODE_LIST(a)}</td></tr>`).join("")}</tbody>`, "Classification");
  }
  if (j.suggested && typeof j.suggested === "object") {
    take("suggested");
    out += heading(2, "suggested", "Suggested pointers");
    out += "<p>The pointers suggested for a grant, by message type.</p>";
    out += wrapTable(`<thead><tr><th>Message type</th><th>Pointers</th></tr></thead><tbody>${Object.entries(j.suggested).map(([t, a]) => `<tr><td>${code(t)}</td><td>${a.length ? a.map((x) => code(x)).join("<br>") : "(none)"}</td></tr>`).join("")}</tbody>`, "Suggested pointers");
  }
  for (const k of Object.keys(j)) if (!handled.has(k) && !["description", "types", "replies", "limits_schema", "classification", "suggested"].includes(k)) { cov.cover("", k, "other"); cov.others.push({ pointer: "", key: k, value: j[k] }); }
  out += otherKeywords(ctx, "this scope definition");
  out += heading(2, "full-schema", "Full file") + sourceDetails(file.text, "schema-source", `${file.rel} as published`);
  return { body: out, cov, problems, outline: outlineOf(out) };
}

// ---------------------------------------------------------------------------------------------------------
// schemas/client/tools.json

export function toolsPage({ file, resolveRef, servedAt, restLink }) {
  const problems = [];
  const ctx = makeCtx({ resolveRef, problems });
  const cov = ctx.cov;
  const j = file.json;
  let out = "";
  const handledRoot = new Set();
  const take = (k) => { handledRoot.add(k); cov.cover("", k, "table"); };
  const rows = [];
  if ("alp" in j) { take("alp"); rows.push(["Protocol version", code(j.alp)]); }
  rows.push(["Served at", `<a href="${esc(servedAt)}">${esc(servedAt)}</a>`]);
  if (restLink) rows.push(["REST mirror", `<a href="${esc(restLink)}">The same tools as HTTPS endpoints</a>`]);
  out += facts(rows);
  if ("description" in j) { take("description"); out += `<p>${inlineMd(j.description)}</p>`; }
  if ("untrusted_notice" in j) { take("untrusted_notice"); out += `<p class="hint-p"><strong>Untrusted notice</strong> that results carry: ${inlineMd(j.untrusted_notice)}</p>`; }

  const tools = Array.isArray(j.tools) ? j.tools : [];
  take("tools");
  cov.cover("", "tools", "subsection");
  out += heading(2, "tools", "Tools");
  out += wrapTable(`<thead><tr><th>Tool</th><th>Title</th><th>Reads only</th></tr></thead><tbody>${tools.map((t) => `<tr><td><a href="#${esc(ctxId(t.name))}">${code(t.name)}</a></td><td>${inlineMd(t.title ?? "")}</td><td>${t.annotations?.readOnlyHint === true ? "yes" : "no"}</td></tr>`).join("")}</tbody>`, "Tools");

  tools.forEach((t, i) => {
    const tp = ptr("", "tools", i);
    const id = ctxId(t.name);
    out += heading(2, id, code(t.name));
    if ("name" in t) cov.cover(tp, "name", "table");
    if ("title" in t) { cov.cover(tp, "title", "table"); out += `<p class="schema-title"><strong>${inlineMd(t.title)}</strong></p>`; }
    if ("description" in t) { cov.cover(tp, "description", "table"); out += `<p>${inlineMd(t.description)}</p>`; }
    if (t.annotations && typeof t.annotations === "object") {
      cov.cover(tp, "annotations", "table");
      out += heading(3, `${id}-annotations`, "Annotations");
      out += wrapTable(`<thead><tr><th>Annotation</th><th>Value</th></tr></thead><tbody>${Object.entries(t.annotations).map(([k, v]) => `<tr><td>${code(k)}</td><td>${jcode(v)}</td></tr>`).join("")}</tbody>`, "Annotations");
    }
    if ("inputSchema" in t) {
      cov.cover(tp, "inputSchema", "subsection");
      out += heading(3, `${id}-input`, "Input");
      ctx.idPrefix = `${t.name} input `;
      out += schemaBlock(t.inputSchema, ptr(tp, "inputSchema"), ctx, { level: 4 });
    }
    if ("outputSchema" in t) {
      cov.cover(tp, "outputSchema", "subsection");
      out += heading(3, `${id}-output`, "Output");
      ctx.idPrefix = `${t.name} output `;
      out += `<details class="source"><summary>Result members of ${esc(t.name)}</summary>${schemaBlock(t.outputSchema, ptr(tp, "outputSchema"), ctx, { level: 4 })}</details>`;
    }
    ctx.idPrefix = "";
    for (const k of Object.keys(t)) if (!["name", "title", "description", "annotations", "inputSchema", "outputSchema"].includes(k)) { cov.cover(tp, k, "other"); cov.others.push({ pointer: tp, key: k, value: t[k] }); }
  });
  for (const k of Object.keys(j)) if (!handledRoot.has(k)) { cov.cover("", k, "other"); cov.others.push({ pointer: "", key: k, value: j[k] }); }
  out += otherKeywords(ctx, "this file");
  out += heading(2, "full-file", "Full file") + sourceDetails(file.text, "schema-source", `${file.rel} as published`);
  return { body: out, cov, problems, outline: outlineOf(out) };
}

const ctxId = (name) => new Slugger().slug(`tool-${name}`);

// ---------------------------------------------------------------------------------------------------------
// schemas/client/openapi.json (the REST mirror)

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/** Where each REST body is shown: "same" when its schema equals a tool's input or output, else in full. */
export function restPage({ file, tools, resolveRef, servedAt, toolsLink, markdown }) {
  const problems = [];
  const ctx = makeCtx({ resolveRef, problems });
  const cov = ctx.cov;
  const j = file.json;
  const handled = new Set();
  const take = (k, where = "table") => { handled.add(k); cov.cover("", k, where); };
  const struct = (obj, p, known) => {
    for (const k of Object.keys(obj)) {
      if (known.includes(k)) cov.cover(p, k, "table");
      else { cov.cover(p, k, "other"); cov.others.push({ pointer: p, key: k, value: obj[k] }); }
    }
  };
  const toolByName = new Map((tools?.tools || []).map((t, i) => [t.name, { tool: t, i }]));
  let out = "";

  take("openapi"); take("info", "table");
  const info = j.info || {};
  const rows = [["OpenAPI", code(j.openapi)], ["Title", inlineMd(info.title ?? "")], ["Version", code(info.version ?? "")]];
  if (info.license) rows.push(["License", `${esc(info.license.name ?? "")}${info.license.identifier ? ` (${code(info.license.identifier)})` : ""}`]);
  if ("jsonSchemaDialect" in j) { take("jsonSchemaDialect"); rows.push(["JSON Schema dialect", `<code class="pattern">${esc(j.jsonSchemaDialect)}</code>`]); }
  rows.push(["Served at", `<a href="${esc(servedAt)}">${esc(servedAt)}</a>`]);
  if (toolsLink) rows.push(["Tools", `<a href="${esc(toolsLink)}">The same operations as MCP tools</a>`]);
  out += facts(rows);
  struct(info, "/info", ["title", "version", "license", "description"]);
  if (info.license) struct(info.license, "/info/license", ["name", "identifier"]);
  if (info.description) out += markdown(info.description);

  if (Array.isArray(j.servers)) {
    take("servers");
    out += heading(2, "servers", "Servers");
    out += wrapTable(`<thead><tr><th>URL</th><th>Variable</th><th>Default</th></tr></thead><tbody>${j.servers.flatMap((s, i) => {
      struct(s, ptr("", "servers", i), ["url", "variables", "description"]);
      const vars = s.variables ? Object.entries(s.variables) : [];
      for (const [name, v] of vars) struct(v, ptr(ptr("", "servers", i), "variables", name), ["default", "enum", "description"]);
      if (!vars.length) return [`<tr><td>${code(s.url)}</td><td></td><td></td></tr>`];
      return vars.map(([name, v]) => `<tr><td>${code(s.url)}</td><td>${code(name)}</td><td>${code(v.default ?? "")}</td></tr>`);
    }).join("")}</tbody>`, "Servers");
  }

  // Operations.
  const ops = [];
  take("paths", "subsection");
  for (const [pathName, item] of Object.entries(j.paths || {})) {
    const pp = ptr("/paths", pathName);
    struct(item, pp, METHODS);
    for (const m of METHODS) if (item[m]) ops.push({ path: pathName, method: m, op: item[m], pointer: ptr(pp, m) });
  }
  const securityText = (sec) => {
    if (!Array.isArray(sec)) return "";
    return sec.map((alt) => Object.entries(alt).map(([name, scopes]) => `${code(name)}${scopes.length ? ` (${scopes.map((s) => esc(s)).join(", ")})` : ""}`).join(" and ")).join(" or ");
  };
  out += heading(2, "operations", "Operations");
  out += wrapTable(`<thead><tr><th>Method</th><th>Path</th><th>Operation</th><th>Summary</th><th>Authentication</th></tr></thead><tbody>${ops.map((o) => `<tr><td><span class="method">${esc(o.method.toUpperCase())}</span></td><td><code>${esc(o.path)}</code></td><td><a href="#${esc(opId(o))}">${code(o.op.operationId ?? o.path)}</a></td><td>${inlineMd(o.op.summary ?? "")}</td><td>${securityText(o.op.security)}</td></tr>`).join("")}</tbody>`, "Operations");
  out += `<p>Authentication is one of the listed alternatives: ${code("oauth")} is an OAuth 2.1 access token with the scope shown, ${code("pat")} a personal access token. Both are described under <a href="#security-schemes">Security schemes</a>.</p>`;

  for (const o of ops) {
    const { op, pointer } = o;
    out += heading(3, opId(o), `<span class="method">${esc(o.method.toUpperCase())}</span> <code>${esc(o.path)}</code>`);
    struct(op, pointer, ["operationId", "summary", "description", "security", "requestBody", "responses", "parameters", "tags", "deprecated"]);
    const tool = toolByName.get(op.operationId);
    if (op.summary) out += `<p class="schema-title"><strong>${inlineMd(op.summary)}</strong></p>`;
    if (op.description) {
      if (tool && tool.tool.description === op.description) out += `<p>The same description as the tool ${code(tool.tool.name)} (<a href="${esc(toolsLink)}#${esc(ctxId(tool.tool.name))}">Client tools</a>).</p>`;
      else out += `<p>${inlineMd(op.description)}</p>`;
    }
    if (op.security) out += `<p>Authentication: ${securityText(op.security) || "none"}.</p>`;
    if (Array.isArray(op.security)) op.security.forEach((alt, i) => struct(alt, ptr(pointer, "security", i), Object.keys(alt)));
    if (Array.isArray(op.parameters) && op.parameters.length) {
      out += heading(4, `${opId(o)}-parameters`, "Parameters");
      out += wrapTable(`<thead><tr><th>Name</th><th>In</th><th>Required</th><th>Description</th></tr></thead><tbody>${op.parameters.map((pa, i) => { struct(pa, ptr(pointer, "parameters", i), ["name", "in", "required", "description", "schema"]); return `<tr><td>${code(pa.name ?? "")}</td><td>${esc(pa.in ?? "")}</td><td>${pa.required ? "yes" : ""}</td><td>${inlineMd(pa.description ?? "")}</td></tr>`; }).join("")}</tbody>`, "Parameters");
    }
    if (op.requestBody) {
      const rp = ptr(pointer, "requestBody");
      struct(op.requestBody, rp, ["required", "content", "description"]);
      out += heading(4, `${opId(o)}-request`, "Request body");
      out += `<p>${op.requestBody.required ? "Required." : "Optional."}</p>`;
      for (const [mt, media] of Object.entries(op.requestBody.content || {})) {
        const mp = ptr(ptr(rp, "content"), mt);
        struct(media, mp, ["schema", "examples"]);
        out += bodyBlock({ media, mt, mp, ctx, tool: tool?.tool, which: "inputSchema", toolsLink, level: 5, idPrefix: `${opId(o)} request ` });
        out += examplesHtml(media, mp, struct);
      }
    }
    if (op.responses) {
      out += heading(4, `${opId(o)}-responses`, "Responses");
      const rows2 = [];
      const blocks = [];
      for (const [codeName, resp] of Object.entries(op.responses)) {
        const rsp = ptr(ptr(pointer, "responses"), codeName);
        if (resp && "$ref" in resp) {
          struct(resp, rsp, ["$ref", "description", "summary"]);
          const target = refTarget(j, resp.$ref);
          const note = [resp.summary, resp.description].filter(Boolean).map((t) => inlineMd(t)).join(" ");
          rows2.push(`<tr><td>${code(codeName)}</td><td>${note ? note + " " : ""}<span class="hint">Body:</span> ${target ? `<a href="#${esc(componentId(resp.$ref))}">${esc(resp.$ref.split("/").pop())}</a>` : esc(resp.$ref)}</td><td></td></tr>`);
          if (!target) problems.push(`openapi ${rsp}: can't resolve ${resp.$ref}`);
          continue;
        }
        struct(resp, rsp, ["description", "content", "headers"]);
        const media = Object.entries(resp.content || {});
        rows2.push(`<tr><td>${code(codeName)}</td><td>${inlineMd(resp.description ?? "")}</td><td>${media.map(([mt]) => code(mt)).join(" ")}</td></tr>`);
        for (const [mt, m] of media) {
          const mp = ptr(ptr(rsp, "content"), mt);
          struct(m, mp, ["schema", "examples"]);
          blocks.push(bodyBlock({ media: m, mt, mp, ctx, tool: tool?.tool, which: "outputSchema", toolsLink, level: 5, idPrefix: `${opId(o)} response ${codeName} `, label: `Response ${codeName}` }) + examplesHtml(m, mp, struct));
        }
      }
      out += wrapTable(`<thead><tr><th>Status</th><th>Meaning</th><th>Content</th></tr></thead><tbody>${rows2.join("")}</tbody>`, "Responses");
      out += blocks.join("");
    }
  }

  // Components.
  if (j.components) {
    take("components", "subsection");
    struct(j.components, "/components", ["securitySchemes", "responses"]);
    const sec = j.components.securitySchemes || {};
    out += heading(2, "security-schemes", "Security schemes");
    for (const [name, s] of Object.entries(sec)) {
      const sp = ptr("/components/securitySchemes", name);
      struct(s, sp, ["type", "description", "scheme", "flows", "bearerFormat", "in", "name"]);
      const rows3 = [["Type", code(s.type ?? "")]];
      if (s.scheme) rows3.push(["Scheme", code(s.scheme)]);
      out += heading(3, `security-${name}`, code(name));
      if (s.description) out += `<p>${inlineMd(s.description)}</p>`;
      if (s.flows) {
        struct(s.flows, ptr(sp, "flows"), ["implicit", "password", "clientCredentials", "authorizationCode"]);
        for (const [flow, f] of Object.entries(s.flows)) {
          const fp = ptr(ptr(sp, "flows"), flow);
          struct(f, fp, ["authorizationUrl", "tokenUrl", "refreshUrl", "scopes"]);
          rows3.push(["Flow", code(flow)]);
          if (f.authorizationUrl) rows3.push(["Authorization URL", code(f.authorizationUrl)]);
          if (f.tokenUrl) rows3.push(["Token URL", code(f.tokenUrl)]);
          if (f.refreshUrl) rows3.push(["Refresh URL", code(f.refreshUrl)]);
          for (const [scope, d] of Object.entries(f.scopes || {})) rows3.push([`Scope ${code(scope)}`, inlineMd(d)]);
        }
      }
      out += facts(rows3);
    }
    for (const [name, resp] of Object.entries(j.components.responses || {})) {
      const rp = ptr("/components/responses", name);
      const id = componentId(`#/components/responses/${name}`);
      struct(resp, rp, ["description", "content"]);
      out += heading(2, id, `Response <code>${esc(name)}</code>`);
      if (resp.description) out += `<p>${inlineMd(resp.description)}</p>`;
      for (const [mt, m] of Object.entries(resp.content || {})) {
        const mp = ptr(ptr(rp, "content"), mt);
        struct(m, mp, ["schema", "examples"]);
        ctx.idPrefix = `${name} `;
        out += `<p>Content type ${code(mt)}.</p>${schemaBlock(m.schema, ptr(mp, "schema"), ctx, { level: 3 })}`;
        cov.cover(mp, "schema", "subsection");
        ctx.idPrefix = "";
      }
    }
  }
  for (const k of Object.keys(j)) if (!handled.has(k)) { cov.cover("", k, "other"); cov.others.push({ pointer: "", key: k, value: j[k] }); }
  out += otherKeywords(ctx, "this file");
  out += heading(2, "full-file", "Full file") + sourceDetails(file.text, "schema-source", `${file.rel} as published`);
  return { body: out, cov, problems, outline: outlineOf(out) };
}

/** The named examples of a media type: each one's summary and its value, as published in the file. */
function examplesHtml(media, mp, struct) {
  if (!media.examples || typeof media.examples !== "object") return "";
  const ep = ptr(mp, "examples");
  return `<p class="rules-label">Examples</p>${Object.entries(media.examples).map(([name, ex]) => {
    struct(ex, ptr(ep, name), ["summary", "description", "value", "externalValue"]);
    const title = [name, ex.summary].filter(Boolean).map((t) => esc(t)).join(": ");
    return `<details class="source"><summary>${title}</summary>${ex.description ? `<p>${inlineMd(ex.description)}</p>` : ""}${"value" in ex ? `<pre tabindex="0"><code class="language-json">${highlightJson(JSON.stringify(ex.value, null, 2))}</code></pre>` : ""}</details>`;
  }).join("")}`;
}

const opId = (o) => new Slugger().slug(`op-${o.op.operationId ?? o.method + o.path}`);
const componentId = (ref) => new Slugger().slug(`response-${ref.split("/").pop()}`);
function refTarget(j, ref) {
  if (!ref.startsWith("#/")) return null;
  let cur = j;
  for (const seg of ref.slice(2).split("/")) { if (cur === null || typeof cur !== "object") return null; cur = cur[seg.replace(/~1/g, "/").replace(/~0/g, "~")]; }
  return cur ?? null;
}

/** A request or response body: "the same schema as the tool's" (checked) or the schema in full. */
function bodyBlock({ media, mt, mp, ctx, tool, which, toolsLink, level, idPrefix, label }) {
  const sp = ptr(mp, "schema");
  const head = `<p>${label ? esc(label) + ", " : ""}content type ${code(mt)}.</p>`;
  if (media.schema === undefined) return head;
  if (tool && deepEqual(media.schema, tool[which])) {
    // Shown on the tools page: every keyword is accounted for there, and the two schemas are identical.
    coverSubtree(media.schema, sp, ctx.cov, "same-as-tool");
    ctx.cov.cover(mp, "schema", "table");
    const what = which === "inputSchema" ? "input" : "output";
    return `${head}<p>The schema is identical to the ${what} of the tool ${code(tool.name)}: see <a href="${esc(toolsLink)}#${esc(ctxId(tool.name) + "-" + what)}">${esc(what === "input" ? "Input" : "Output")} of ${esc(tool.name)}</a>.</p>`;
  }
  ctx.cov.cover(mp, "schema", "subsection");
  ctx.idPrefix = idPrefix;
  const html = schemaBlock(media.schema, sp, ctx, { level });
  ctx.idPrefix = "";
  return head + html;
}

// ---------------------------------------------------------------------------------------------------------
// The schemas index

/** The index table: file, title, what it defines (from Appendix B). rows: appendixBRows. entries: { rel, title, url }. */
export function schemasIndex({ entries, rows, link }) {
  const out = [];
  const problems = [];
  const groups = new Map();
  for (const e of entries) {
    const row = appendixRowFor(rows, e.rel);
    if (!row) { problems.push(`${e.rel}: has no row in Appendix B of the specification`); continue; }
    if (!groups.has(row)) groups.set(row, []);
    groups.get(row).push(e);
  }
  for (const [row, list] of groups) {
    list.forEach((e, i) => {
      const defines = i === 0 ? `<td${list.length > 1 ? ` rowspan="${list.length}"` : ""}>${inlineMd(row.defines)}</td>` : "";
      out.push(`<tr><td><a href="${esc(link(e.url))}"><code>${esc(e.rel.replace(/^schemas\//, ""))}</code></a></td><td>${inlineMd(e.title)}</td>${defines}</tr>`);
    });
  }
  const html = wrapTable(`<thead><tr><th>File</th><th>Title</th><th>Defines</th></tr></thead><tbody>${out.join("")}</tbody>`, "Schemas");
  return { html, problems };
}

// ---------------------------------------------------------------------------------------------------------
// The vectors index

/** README rows: Map(file -> first sentence of the "what a conforming implementation must reproduce" cell). */
export function vectorReadmeRows(readme) {
  const out = new Map();
  for (const m of readme.matchAll(/^\| `([^`]+)` \| (.*) \|$/gm)) {
    const cell = m[2];
    const s = /^(.*?[a-z0-9)`"])\.(\s|$)/.exec(cell);
    out.set(m[1], s ? s[1] + "." : cell);
  }
  return out;
}

export function vectorsIndex({ root, readme, notes, hrefHtml, hrefMd }) {
  const rows = vectorReadmeRows(readme);
  const problems = [];
  const files = filesUnder(root, "vectors").filter((f) => f.endsWith(".json"));
  const tr = [];
  const mdRows = [];
  let totalCases = 0, caseFiles = 0;
  for (const f of files) {
    const rel = f.replace(/^vectors\//, "");
    const isKeys = rel.startsWith("keys/");
    const isWorld = rel === "world.json";
    let cases = "", casesMd = "";
    if (isKeys) { cases = "keys"; casesMd = "keys"; }
    else {
      const j = JSON.parse(fs.readFileSync(path.join(root, f), "utf8"));
      if (isWorld) { cases = "fixture"; casesMd = "fixture"; }
      else {
        const c = vectorCaseCount(j);
        totalCases += c.total; caseFiles++;
        const plain = c.parts.length === 1 && c.parts[0][0] === "cases";
        cases = !c.parts.length ? "1 scenario" : plain ? String(c.total) : `${c.total} <span class="hint">(${c.parts.map(([k, n]) => `${esc(k)} ${n}`).join(", ")})</span>`;
        casesMd = !c.parts.length ? "1 scenario" : plain ? String(c.total) : `${c.total} (${c.parts.map(([k, n]) => `${k} ${n}`).join(", ")})`;
      }
    }
    let covers = rows.get(rel);
    if (!covers) covers = notes[rel] || "";
    if (!covers) problems.push(`${f}: has no row in vectors/README.md and no note in site.config.mjs vectorNotes`);
    tr.push(`<tr><td><a href="${esc(hrefHtml(rel, isKeys))}"><code>${esc(rel)}</code></a></td><td>${cases}</td><td>${inlineMd(covers)}</td></tr>`);
    mdRows.push(`| [\`${rel}\`](${hrefMd(rel, isKeys)}) | ${casesMd} | ${covers.replace(/\|/g, "\\|")} |`);
  }
  const html = wrapTable(`<thead><tr><th>File</th><th>Cases</th><th>What it covers</th></tr></thead><tbody>${tr.join("")}</tbody>`, "Vector files");
  const md = `| File | Cases | What it covers |\n|---|---|---|\n${mdRows.join("\n")}`;
  return { html, md, totalCases, caseFiles, problems };
}

// ---------------------------------------------------------------------------------------------------------
// The glossary

/** The defined terms of Section 2: [{ term, definition }] in the specification's order. */
export function glossaryTerms(specMd) {
  const start = specMd.indexOf("\n## 2. Terminology");
  const end = specMd.indexOf("\n---", start);
  if (start === -1 || end === -1) throw new Error("spec/alp-v0.1.md: Section 2 not found, so the glossary can't be built");
  const terms = [];
  for (const para of specMd.slice(start, end).split(/\n\n+/)) {
    const m = /^\*\*(.+?)\.\*\* ([\s\S]+)$/.exec(para.trim());
    if (m) terms.push({ term: m[1], definition: m[2].trim() });
  }
  return terms;
}

export const termSortKey = (t) => t.term.replace(/`/g, "").toLowerCase();

/** The glossary as Markdown (alphabetical): a level-2 heading per term, then its definition. */
export function glossaryMarkdown(terms) {
  const sorted = [...terms].sort((a, b) => (termSortKey(a) < termSortKey(b) ? -1 : termSortKey(a) > termSortKey(b) ? 1 : 0));
  return sorted.map((t) => `## ${t.term}\n\n${t.definition}\n`).join("\n");
}

// ---------------------------------------------------------------------------------------------------------
// The reference index

/** Headings of a numbered range ("13.1".."13.9"): [{ number, text, id }] from the specification's headings. */
export function headingsInSection(headings, prefix) {
  return headings.filter((h) => h.number && h.number.startsWith(prefix + ".") && h.number.split(".").length === 2);
}
