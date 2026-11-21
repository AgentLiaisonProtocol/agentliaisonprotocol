// The reference pages must be faithful before they are pretty: a schema page that silently leaves out a
// constraint misleads an implementer. These tests walk every schema file with a walker written here (not the
// one the generator uses), collect every keyword in the file, and assert that the page's data model accounts
// for it: shown in a table, shown in a subsection, or listed under "Other keywords".

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { textContent } from "../lib/html.mjs";
import { applyCounts, computeCounts, requirementCounts, vectorCaseCount } from "../lib/counts.mjs";
import { Coverage, describe, makeCtx, ptr, schemaBlock } from "../lib/schemas.mjs";
import {
  appendixBRows, appendixRowFor, glossaryMarkdown, glossaryTerms, loadSchemaFiles, makeResolver, restPage, schemaPage, scopePage, toolsPage, vectorReadmeRows,
} from "../lib/reference.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const spec = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
const files = loadSchemaFiles(ROOT);
const byRel = new Map(files.map((f) => [f.rel, f]));

// ---- an independent walk of a JSON Schema: every (pointer, keyword) in it ------------------------------------
const esc = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");
function schemaKeywords(node, pointer, out) {
  if (typeof node === "boolean") { out.push([pointer, "(boolean)"]); return out; }
  assert.ok(node && typeof node === "object" && !Array.isArray(node), `${pointer} is not a schema`);
  for (const k of Object.keys(node)) out.push([pointer, k]);
  for (const k of ["properties", "patternProperties", "$defs", "dependentSchemas"]) {
    for (const [name, sub] of Object.entries(node[k] ?? {})) schemaKeywords(sub, `${pointer}/${k}/${esc(name)}`, out);
  }
  for (const k of ["allOf", "anyOf", "oneOf", "prefixItems"]) (node[k] ?? []).forEach((sub, i) => schemaKeywords(sub, `${pointer}/${k}/${i}`, out));
  for (const k of ["items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "if", "then", "else", "not", "contains", "propertyNames", "additionalItems"]) {
    if (k in node) schemaKeywords(node[k], `${pointer}/${k}`, out);
  }
  return out;
}

/** Every schema node of a file: [pointer, node]. */
function schemaNodes(node, pointer, out = []) {
  out.push([pointer, node]);
  if (!node || typeof node !== "object") return out;
  for (const k of ["properties", "patternProperties", "$defs", "dependentSchemas"]) for (const [n, sub] of Object.entries(node[k] ?? {})) schemaNodes(sub, `${pointer}/${k}/${esc(n)}`, out);
  for (const k of ["allOf", "anyOf", "oneOf", "prefixItems"]) (node[k] ?? []).forEach((sub, i) => schemaNodes(sub, `${pointer}/${k}/${i}`, out));
  for (const k of ["items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "if", "then", "else", "not", "contains", "propertyNames", "additionalItems"]) if (k in node) schemaNodes(node[k], `${pointer}/${k}`, out);
  return out;
}

/** The keywords a whole file is expected to have accounted for: [pointer, keyword] and the schema roots. */
function expectedFor(file) {
  const j = file.json;
  const out = [];
  const roots = [];
  if (file.rel === "schemas/client/tools.json") {
    for (const k of Object.keys(j)) out.push(["", k]);
    j.tools.forEach((t, i) => {
      for (const k of Object.keys(t)) out.push([`/tools/${i}`, k]);
      for (const which of ["inputSchema", "outputSchema"]) { schemaKeywords(t[which], `/tools/${i}/${which}`, out); roots.push([`/tools/${i}/${which}`, t[which]]); }
    });
  } else if (file.rel === "schemas/client/openapi.json") {
    structural(j, "", out, roots);
  } else if (file.rel.startsWith("schemas/scopes/")) {
    for (const k of Object.keys(j)) out.push(["", k]);
    for (const [t, def] of Object.entries(j.types)) {
      for (const k of Object.keys(def)) out.push([`/types/${t}`, k]);
      schemaKeywords(def.schema, `/types/${t}/schema`, out); roots.push([`/types/${t}/schema`, def.schema]);
    }
    if (j.limits_schema !== undefined) { schemaKeywords(j.limits_schema, "/limits_schema", out); roots.push(["/limits_schema", j.limits_schema]); }
  } else {
    schemaKeywords(j, "", out); roots.push(["", j]);
  }
  return { keywords: out, roots };
}

// OpenAPI: an object's keys are keywords, except the keys of the containers that are maps of names; `schema`
// values are JSON Schemas. This walk is independent of the generator's.
const MAPS = new Set(["paths", "responses", "content", "securitySchemes", "variables", "scopes", "examples"]);
function structural(node, pointer, out, roots) {
  if (Array.isArray(node)) { node.forEach((x, i) => structural(x, `${pointer}/${i}`, out, roots)); return; }
  if (!node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    out.push([pointer, k]);
    const child = `${pointer}/${esc(k)}`;
    if (k === "schema") { schemaKeywords(v, child, out); roots.push([child, v]); continue; }
    if (k === "value") continue; // an example's value is data, not a keyword of the document
    if (MAPS.has(k) && v && typeof v === "object") {
      if (k === "scopes") continue; // oauth scope names and their descriptions: data, shown as rows
      for (const [name, sub] of Object.entries(v)) {
        if (sub && typeof sub === "object" && !Array.isArray(sub)) {
          structural(sub, `${child}/${esc(name)}`, out, roots);
        }
      }
      continue;
    }
    if (k === "security" && Array.isArray(v)) { v.forEach((alt, i) => { for (const name of Object.keys(alt)) out.push([`${child}/${i}`, name]); }); continue; }
    if (v && typeof v === "object") structural(v, child, out, roots);
  }
}

// ---- building every page the way the build does ----------------------------------------------------------------
const pageUrlFor = (rel) => `/p/${rel}/`;
const resolver = (rel) => makeResolver({ files, pageUrlFor, currentFile: rel, link: (u) => u });

function buildPage(file) {
  const resolveRef = resolver(file.rel);
  const servedAt = `https://agentliaisonprotocol.org/${file.rel}`;
  if (file.rel === "schemas/client/tools.json") return toolsPage({ file, resolveRef, servedAt, restLink: "/rest/" });
  if (file.rel === "schemas/client/openapi.json") {
    return restPage({ file, tools: byRel.get("schemas/client/tools.json").json, resolveRef, servedAt, toolsLink: "/tools/", markdown: (md) => `<p>${md.length}</p>` });
  }
  if (file.rel.startsWith("schemas/scopes/")) return scopePage({ file, resolveRef, servedAt, link: (u) => u });
  return schemaPage({ file, resolveRef, servedAt });
}

test("there are schema files to check", () => {
  assert.ok(files.length >= 28, `found ${files.length} files under schemas/`);
});

for (const file of files) {
  test(`${file.rel}: every keyword in the file is shown, in a subsection or listed under Other keywords`, () => {
    const built = buildPage(file);
    assert.deepEqual(built.problems, [], "the page reported problems");
    const { keywords } = expectedFor(file);
    assert.ok(keywords.length > 0);
    const missing = keywords.filter(([p, k]) => !built.cov.has(p, k)).map(([p, k]) => `${p || "(root)"} ${k}`);
    assert.deepEqual(missing, [], `keywords the page doesn't account for in ${file.rel}`);
  });

  test(`${file.rel}: values of constraints appear in the page text`, () => {
    const built = buildPage(file);
    const text = textContent(built.body.replace(/<details class="source" id="schema-source">[\s\S]*?<\/details>/, ""));
    const { roots } = expectedFor(file);
    const problems = [];
    for (const [rootPointer, root] of roots) {
      for (const [pointer, node] of schemaNodes(root, rootPointer)) {
        if (!node || typeof node !== "object") continue;
        // A REST body identical to a tool's schema is shown on the tools page (and checked below).
        if ([...(built.cov.map.get(pointer)?.values() ?? [])].includes("same-as-tool")) continue;
        for (const k of ["pattern"]) if (typeof node[k] === "string" && !text.includes(node[k])) problems.push(`${pointer} pattern ${node[k]}`);
        for (const k of ["const", "default"]) if (k in node && !text.includes(JSON.stringify(node[k]))) problems.push(`${pointer} ${k} ${JSON.stringify(node[k])}`);
        if (Array.isArray(node.enum)) for (const v of node.enum) if (!text.includes(JSON.stringify(v))) problems.push(`${pointer} enum ${JSON.stringify(v)}`);
        for (const k of ["format", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minItems", "maxItems", "uniqueItems", "minContains", "maxContains", "minProperties", "maxProperties"]) {
          if (k in node && !new RegExp(`${k}\\s+${JSON.stringify(node[k]).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(text)) problems.push(`${pointer} ${k} ${JSON.stringify(node[k])}`);
        }
        for (const k of Object.keys(node)) if (k.startsWith("x-") && !text.includes(k)) problems.push(`${pointer} ${k}`);
        if (Array.isArray(node.required)) for (const r of node.required) if (!text.includes(r)) problems.push(`${pointer} required ${r}`);
      }
    }
    assert.deepEqual(problems, [], "values missing from the page text");
  });

  test(`${file.rel}: the Other keywords section says there are none, or lists each`, () => {
    const built = buildPage(file);
    const m = /<h2 id="other-keywords">[\s\S]*?(?=<h2 id="full-)/.exec(built.body);
    assert.ok(m, "no Other keywords section");
    if (!built.cov.others.length) assert.match(m[0], /None\. Every keyword in/);
    else for (const o of built.cov.others) assert.ok(textContent(m[0]).includes(o.key), `${o.key} is not listed`);
  });
}

test("the REST page names every path, status code, content type, scheme and server variable of the file", () => {
  const rest = byRel.get("schemas/client/openapi.json");
  const text = textContent(buildPage(rest).body.replace(/<details class="source" id="schema-source">[\s\S]*?<\/details>/, ""));
  const names = new Set();
  const j = rest.json;
  for (const [p, item] of Object.entries(j.paths)) {
    names.add(p);
    for (const [method, op] of Object.entries(item)) {
      names.add(method.toUpperCase());
      for (const [codeName, resp] of Object.entries(op.responses)) { names.add(codeName); for (const mt of Object.keys(resp.content ?? {})) names.add(mt); }
      for (const media of Object.values(op.requestBody?.content ?? {})) for (const [n, ex] of Object.entries(media.examples ?? {})) { names.add(n); if (ex.summary) names.add(ex.summary); }
      for (const mt of Object.keys(op.requestBody?.content ?? {})) names.add(mt);
      for (const alt of op.security ?? []) for (const [n, scopes] of Object.entries(alt)) { names.add(n); scopes.forEach((x) => names.add(x)); }
    }
  }
  for (const [n, sch] of Object.entries(j.components.securitySchemes)) { names.add(n); for (const f of Object.values(sch.flows ?? {})) { names.add(f.authorizationUrl); names.add(f.tokenUrl); for (const [scope, d] of Object.entries(f.scopes)) { names.add(scope); names.add(d); } } }
  for (const s of j.servers) { names.add(s.url); for (const [n, v] of Object.entries(s.variables ?? {})) { names.add(n); names.add(v.default); } }
  for (const n of Object.keys(j.components.responses)) names.add(n);
  const missing = [...names].filter((n) => n && !text.includes(n));
  assert.deepEqual(missing, []);
});

test("REST bodies that the page calls identical to a tool's schema are identical", () => {
  const rest = byRel.get("schemas/client/openapi.json");
  const tools = byRel.get("schemas/client/tools.json").json.tools;
  const built = buildPage(rest);
  const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
  let same = 0;
  for (const [pathName, item] of Object.entries(rest.json.paths)) {
    const op = item.post;
    const tool = tools.find((t) => t.name === op.operationId);
    assert.ok(tool, `${op.operationId} has a tool`);
    const bodies = [
      [ptr("/paths", pathName, "post", "requestBody", "content", "application/json", "schema"), op.requestBody.content["application/json"].schema, tool.inputSchema],
      [ptr("/paths", pathName, "post", "responses", "200", "content", "application/json", "schema"), op.responses["200"].content["application/json"].schema, tool.outputSchema],
    ];
    for (const [pointer, schema, toolSchema] of bodies) {
      const claimed = built.cov.map.get(pointer)?.get("type") === "same-as-tool" || built.cov.map.get(pointer)?.get("properties") === "same-as-tool";
      const equal = JSON.stringify(canon(schema)) === JSON.stringify(canon(toolSchema));
      assert.equal(claimed, equal, `${pointer}: the page says ${claimed ? "identical" : "different"}, the files say ${equal ? "identical" : "different"}`);
      if (claimed) same++;
    }
  }
  assert.ok(same > 0);
});

// ---- the generator against synthetic schemas: unknown keywords are never dropped ---------------------------------
const noRef = () => null;
test("an unknown keyword is listed under Other keywords, never dropped", () => {
  const schema = { type: "object", properties: { a: { type: "string", "x-weird": 1, frobnicate: { deep: true } } }, wibble: "x" };
  const ctx = makeCtx({ resolveRef: noRef, problems: [] });
  const html = schemaBlock(schema, "", ctx);
  assert.deepEqual(ctx.cov.others.map((o) => `${o.pointer || "(root)"} ${o.key}`).sort(), ["(root) wibble", "/properties/a frobnicate"]);
  assert.ok(ctx.cov.has("/properties/a", "x-weird"), "x- extension keywords are shown");
  assert.ok(html.includes("x-weird"));
});

test("every JSON Schema 2020-12 applicator and validation keyword is accounted for", () => {
  const schema = {
    $schema: "https://json-schema.org/draft/2020-12/schema", $id: "urn:x", title: "T", description: "D `c`", $comment: "c",
    type: ["object", "null"], required: ["a", "z"], additionalProperties: { type: "integer" }, minProperties: 1, maxProperties: 9, propertyNames: { pattern: "^[a-z]+$" },
    patternProperties: { "^x-": { type: "string" } }, dependentRequired: { a: ["b"] }, dependentSchemas: { a: { required: ["c"] } },
    properties: {
      a: {
        type: "array", items: { type: "object", required: ["q"], properties: { q: { const: 1 }, r: { properties: { s: { properties: { t: { type: "string" } } } } } } },
        prefixItems: [{ type: "string" }], contains: { const: 3 }, minContains: 1, maxContains: 2, minItems: 0, maxItems: 5, uniqueItems: true, default: [], examples: [[1]],
      },
      b: { type: "number", minimum: 0, maximum: 5, exclusiveMinimum: -1, exclusiveMaximum: 6, multipleOf: 0.5, deprecated: true, readOnly: true, writeOnly: false },
      c: { enum: ["x", 1, null], format: "date", minLength: 1, maxLength: 3, pattern: "^x$" },
      d: false, e: true,
      f: { allOf: [{ type: "string" }], anyOf: [{ const: 1 }, { const: 2 }], oneOf: [{ type: "string" }, { type: "number" }], not: { const: 0 }, if: { type: "string" }, then: { minLength: 1 }, else: { type: "integer" } },
    },
    $defs: { d1: { type: "string" } },
  };
  const ctx = makeCtx({ resolveRef: noRef, problems: [] });
  schemaBlock(schema, "", ctx, { skip: new Set(["$defs"]) });
  const cov2 = ctx.cov;
  cov2.cover("", "$defs", "subsection");
  const missing = schemaKeywords(schema, "", []).filter(([p, k]) => !cov2.has(p, k) && !p.startsWith("/$defs/") && !(p === "" && k === "$defs"));
  assert.deepEqual(missing.map(([p, k]) => `${p} ${k}`), []);
  assert.deepEqual(cov2.others, []);
});

test("describe records a boolean schema", () => {
  const ctx = makeCtx({ resolveRef: noRef, problems: [] });
  assert.match(describe(false, "/x", ctx)[0], /not allowed/);
  assert.ok(ctx.cov.has("/x", "(boolean)"));
  assert.ok(new Coverage().lines().length === 0);
});

// ---- links between schemas, the index, the vectors, the glossary and the counts ----------------------------------------
test("every $ref in every schema resolves to a page, and to a definition that exists", () => {
  const unresolved = [];
  for (const file of files) {
    const resolve = resolver(file.rel);
    const walk = (v, p) => {
      if (Array.isArray(v)) return v.forEach((x, i) => walk(x, `${p}/${i}`));
      if (!v || typeof v !== "object") return;
      if (typeof v.$ref === "string" && !file.rel.endsWith("openapi.json") && !resolve(v.$ref)) unresolved.push(`${file.rel} ${p}: ${v.$ref}`);
      for (const [k, x] of Object.entries(v)) walk(x, `${p}/${k}`);
    };
    walk(file.json, "");
  }
  assert.deepEqual(unresolved, []);
});

test("every file under schemas/ has a row in the specification's Appendix B", () => {
  const rows = appendixBRows(spec);
  assert.ok(rows.length >= 15);
  const missing = files.filter((f) => !appendixRowFor(rows, f.rel)).map((f) => f.rel);
  assert.deepEqual(missing, []);
  assert.equal(appendixRowFor(rows, "schemas/messages/ack.schema.json").files[0], "schemas/messages/*.schema.json");
  assert.equal(appendixRowFor(rows, "schemas/scopes/meeting-1.json").files[0], "schemas/scopes/*.json");
});

test("the manifest has a page for every file under schemas/", async () => {
  const config = await import("../site.config.mjs");
  const listed = new Set(config.pages.filter((p) => p.options?.file).map((p) => p.options.file));
  assert.deepEqual(files.map((f) => f.rel).filter((r) => !listed.has(r)), []);
  assert.deepEqual([...listed].filter((r) => !byRel.has(r)), []);
});

test("the vector README's rows give each vector file a first sentence", () => {
  const rows = vectorReadmeRows(fs.readFileSync(path.join(ROOT, "vectors/README.md"), "utf8"));
  assert.ok(rows.size >= 14);
  for (const [f, s] of rows) assert.match(s, /\.$/, f);
  assert.deepEqual(vectorCaseCount({ description: "x", cases: [1, 2, 3] }), { total: 3, parts: [["cases", 3]] });
  assert.deepEqual(vectorCaseCount({ a: [1], b: [], c: [1, 2] }), { total: 3, parts: [["a", 1], ["b", 0], ["c", 2]] });
  assert.deepEqual(vectorCaseCount({ envelope: {}, receipt: {} }), { total: 1, parts: [] });
});

test("the glossary lists every term of Section 2, once, alphabetically", () => {
  const terms = glossaryTerms(spec);
  const names = terms.map((t) => t.term);
  assert.ok(names.includes("Principal") && names.includes("Home broker") && names.includes("`principal_id`"));
  assert.equal(new Set(names).size, names.length);
  // independent count: the bold lead-ins of Section 2's paragraphs
  const section = spec.slice(spec.indexOf("\n## 2. Terminology"), spec.indexOf("\n## 3. "));
  assert.equal(names.length, (section.match(/^\*\*[^\n]+?\.\*\* /gm) || []).length);
  const md = glossaryMarkdown(terms);
  const headings = [...md.matchAll(/^## (.+)$/gm)].map((m) => m[1].replace(/`/g, "").toLowerCase());
  assert.deepEqual(headings, [...headings].sort());
  for (const t of terms) assert.ok(md.includes(t.definition), `definition of ${t.term}`);
});

test("counts: requirements per class match an independent count of Section 13's ids", () => {
  const section = spec.slice(spec.indexOf("\n## 13. "), spec.indexOf("\n## 14. "));
  const independent = {};
  for (const m of section.matchAll(/\|\s*([A-Z]{2,3})-\d+\s*\|/g)) independent[m[1]] = (independent[m[1]] || 0) + 1;
  assert.deepEqual(requirementCounts(spec), independent);
  const c = computeCounts(ROOT, spec);
  assert.equal(c.requirementsTotal, Object.values(independent).reduce((a, b) => a + b, 0));
  assert.equal(c.schemaFiles, files.length);
  assert.ok(c.vectorFiles >= 14 && c.vectorCases > c.vectorFiles);
  assert.equal(Object.keys(c).some((k) => k.startsWith("sections")), false);
});

test("count placeholders are replaced, and an unknown one is a problem", () => {
  const problems = [];
  assert.equal(applyCounts("{{count:a}} and {{count:b}}.", { a: 3, b: 0 }, "f.md", problems), "3 and 0.");
  assert.deepEqual(problems, []);
  assert.equal(applyCounts("{{count:nope}}", { a: 1 }, "f.md", problems), "{{count:nope}}");
  assert.equal(problems.length, 1);
  assert.match(problems[0], /f\.md: unknown count placeholder/);
});
