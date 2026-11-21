// Counts the build computes from the repository, so that hand-written pages never carry a number that can
// drift. A page uses one as a placeholder, {{count:name}}, in its Markdown or HTML body (front matter
// excluded); applyCounts() replaces it, and an unknown name is a build problem.
//
//   schemaFiles          JSON files under schemas/ (the schemas, the five scope definitions, tools.json
//                        and openapi.json)
//   vectorFiles          vector files of cases under vectors/ (not the shared fixture world.json, and not
//                        the TEST-ONLY keys)
//   vectorCases          entries of the top-level arrays of those files; a file with no array (a single
//                        scenario) counts as one
//   requirementsBC, requirementsOB, requirementsHB, requirementsNC, requirementsPB, requirementsCD
//                        numbered conformance requirements per class (specification Section 13)
//   requirementsTotal    the sum of those

import fs from "node:fs";
import path from "node:path";

/** Every file under `dir` (relative paths with "/"), sorted. */
export function filesUnder(root, dir) {
  const out = [];
  const rec = (d) => {
    for (const e of fs.readdirSync(path.join(root, d), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const rel = d ? `${d}/${e.name}` : e.name;
      if (e.isDirectory()) rec(rel);
      else out.push(rel);
    }
  };
  rec(dir);
  return out;
}

/** Entries counted as cases in one vector file: the entries of its top-level arrays, or 1 when it has none. */
export function vectorCaseCount(json) {
  const arrays = Object.entries(json).filter(([, v]) => Array.isArray(v));
  if (!arrays.length) return { total: 1, parts: [] };
  return { total: arrays.reduce((n, [, v]) => n + v.length, 0), parts: arrays.map(([k, v]) => [k, v.length]) };
}

/** The numbered requirement ids in Section 13 of the specification, per class prefix. */
export function requirementCounts(specMd) {
  const start = specMd.indexOf("\n## 13. ");
  const end = specMd.indexOf("\n## 14. ");
  if (start === -1 || end === -1) throw new Error("spec/alp-v0.1.md: Section 13 or 14 not found, so the requirements can't be counted");
  const ids = new Map();
  for (const m of specMd.slice(start, end).matchAll(/^\| ([A-Z]{2,3})-(\d+) \|/gm)) {
    if (!ids.has(m[1])) ids.set(m[1], new Set());
    ids.get(m[1]).add(Number(m[2]));
  }
  const out = {};
  for (const [cls, set] of ids) {
    const max = Math.max(...set);
    if (set.size !== max) throw new Error(`spec/alp-v0.1.md: the ${cls} requirements are not numbered 1 to ${max} without gaps`);
    out[cls] = set.size;
  }
  return out;
}

export function computeCounts(root, specMd) {
  const schemaFiles = filesUnder(root, "schemas").filter((f) => f.endsWith(".json")).length;
  const caseFiles = filesUnder(root, "vectors").filter((f) => f.endsWith(".json") && f !== "vectors/world.json" && !f.includes("/keys/"));
  let vectorCases = 0;
  for (const f of caseFiles) vectorCases += vectorCaseCount(JSON.parse(fs.readFileSync(path.join(root, f), "utf8"))).total;

  const req = requirementCounts(specMd);

  const counts = {
    schemaFiles,
    vectorFiles: caseFiles.length,
    vectorCases,
    requirementsBC: req.BC ?? 0,
    requirementsOB: req.OB ?? 0,
    requirementsHB: req.HB ?? 0,
    requirementsNC: req.NC ?? 0,
    requirementsPB: req.PB ?? 0,
    requirementsCD: req.CD ?? 0,
  };
  counts.requirementsTotal = counts.requirementsBC + counts.requirementsOB + counts.requirementsHB + counts.requirementsNC + counts.requirementsPB + counts.requirementsCD;
  return counts;
}

/** Replace every {{count:name}} in `text`; unknown names are pushed to `problems` and left as they are. */
export function applyCounts(text, counts, file, problems) {
  return text.replace(/\{\{count:([A-Za-z0-9]+)\}\}/g, (m, name) => {
    if (!(name in counts)) { problems.push(`${file}: unknown count placeholder ${m} (known: ${Object.keys(counts).join(", ")})`); return m; }
    return String(counts[name]);
  });
}
