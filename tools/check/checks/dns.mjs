// DNS hint checks (Section 4.7). The record is optional; with none, both checks are skipped.
// Licensed under Apache-2.0.
import { pass, bad, inconclusive, skip } from "./common.mjs";
import { documentObject } from "./document.mjs";

export const TXT = /^v=ALP1;[ ]*id=([A-Za-z0-9]{1,32})$/;

function observeTxt(ctx) {
  return ctx.memo("txt", async () => {
    const name = `_alp.${ctx.domain}`;
    let timer;
    const late = new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), ctx.timeoutMs); });
    try {
      const records = await Promise.race([ctx.resolveTxt(name), late]);
      // A TXT record may be split into several character-strings; they are read joined.
      return { name, records: records.map((chunks) => chunks.join("")) };
    } catch (e) {
      if (e && (e.code === "ENODATA" || e.code === "ENOTFOUND")) return { name, records: [] };
      return { name, error: e && e.code ? `DNS lookup failed (${e.code})` : "DNS lookup failed" };
    } finally {
      clearTimeout(timer);
    }
  });
}

export const FAMILY = "dns";

export async function run(ctx) {
  const ids = ctx.idsOf("dns");
  if (!ctx.domain) {
    for (const id of ids) await ctx.check(id, null, () => skip("no domain was given (--broker mode)"));
    return;
  }
  if (ctx.devMap) {
    for (const id of ids) await ctx.check(id, ctx.domain, () => skip("the development host map is in use, so DNS was not consulted"));
    return;
  }
  const subject = `_alp.${ctx.domain}`;

  const grammar = async () => {
    const t = await observeTxt(ctx);
    if (t.error) return { result: inconclusive({ message: t.error }) };
    if (!t.records.length) return { result: skip(`no TXT record at ${t.name} (the record is optional)`) };
    const shown = t.records.map((r) => JSON.stringify(r)).join(", ");
    if (t.records.length > 1) return { result: bad({ message: `${t.records.length} TXT records: ${shown}; peers ignore them all`, expected: "one record" }) };
    const m = TXT.exec(t.records[0]);
    if (!m) return { result: bad({ message: `the record is ${shown}; peers ignore it`, expected: "v=ALP1; id=<1 to 32 letters and digits>" }) };
    return { result: pass({ notes: [`record: ${shown}`] }), id: m[1] };
  };

  await ctx.check("dns.txt-grammar", subject, async () => (await grammar()).result);

  await ctx.check("dns.txt-id-serial", subject, async () => {
    const g = await grammar();
    if (g.result.outcome === "skip") return g.result;
    if (!g.id) return skip("the record is not a valid ALP record (see dns.txt-grammar)");
    const doc = await documentObject(ctx);
    if (!doc || !Number.isInteger(doc.serial)) return skip("no document `serial` to compare with (see document.found and document.schema)");
    if (g.id === String(doc.serial)) return pass();
    return bad({ message: `the record's id is ${g.id}; the document's serial is ${doc.serial}`, expected: String(doc.serial) });
  });
}
