// Renders the spec's worked examples from the vectors and refreshes them in place between
// <!-- example:NAME --> and <!-- /example --> markers. Usage: node examples.mjs <repo>
import fs from "node:fs";
import path from "node:path";

export function renderExamples(repo) {
  const V = (f) => JSON.parse(fs.readFileSync(path.join(repo, "vectors", f), "utf8"));
  const sig = V("signatures/detached-jws.json").cases[0];
  const world = V("world.json");
  const led = V("ledger/matching-ledgers.json");
  const fed = V("federation/acceptance.json").cases;
  const thread = V("threads/meeting-commit.json");
  const byName = (n) => { const c = fed.find((x) => x.name.startsWith(n)); if (!c) throw new Error("no federation case " + n); return JSON.parse(c.request_body); };
  const rogue = byName("wrong broker");
  const j = (o) => JSON.stringify(o, null, 2);
  return {
    a1_envelope: j({ ...sig.object, broker_sig: sig.expected.broker_sig }),
    a1_header: JSON.stringify(sig.expected.protected_header),
    a1_hash: sig.expected.envelope_hash,
    a2_doc: j(world.domain_documents["example.org@42"]),
    a2_receipt: j({ receipt: led.receipt }),
    a2_lee: j(led.ledgers["alp:lee@example.org"][0]),
    a2_pat: j(led.ledgers["alp:pat@partner.example"][1]),
    a4_rogue: j({ id: rogue.id, from: rogue.from, to: rogue.to, aud: rogue.aud, origin_broker: rogue.origin_broker, "…": "other members and broker_sig omitted" }),
    a5_control: j(byName("good: control envelope")),
    a6_terms_hash: thread.expected.terms_hash,
    a6_ratification: j(thread.objects.ratification_ana),
  };
}

export function fill(text, EX) {
  return text.replace(/<!-- example:([a-z0-9_]+) -->([\s\S]*?)<!-- \/example -->/g, (_m, k, inner) => {
    if (!(k in EX)) throw new Error("unknown example " + k);
    const block = inner.trimStart().startsWith("```");
    return `<!-- example:${k} -->` + (block ? "\n```json\n" + EX[k] + "\n```\n" : "`" + EX[k] + "`") + "<!-- /example -->";
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const repo = process.argv[2];
  if (!repo) { console.error("usage: node examples.mjs <repo>"); process.exit(2); }
  const p = path.join(repo, "spec", "alp-v0.1.md");
  const before = fs.readFileSync(p, "utf8");
  const after = fill(before, renderExamples(repo));
  fs.writeFileSync(p, after);
  console.log(before === after ? "examples already current" : "examples refreshed");
}
