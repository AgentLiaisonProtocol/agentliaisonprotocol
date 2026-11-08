// SPDX-License-Identifier: FSL-1.1-ALv2
// SIGHUP reloads the policy files one by one (src/policy-files.ts): a kill switch in a later file applies even when an
// earlier file didn't change. Before, the reload stopped at the first file whose serial hadn't changed.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { ANA, LEE, buildWorld, examplePolicy } from "./demo/world.ts";
import type { OrgPolicy } from "./core/types.ts";
import { PolicyFiles } from "./policy-files.ts";

const dir = mkdtempSync(join(tmpdir(), "alp-policies-"));
after(() => rmSync(dir, { recursive: true, force: true }));

test("two policy files: an unchanged first file is skipped and a kill switch in the second applies; a stale serial or a malformed file keeps its policy while the others load", async () => {
  const w = await buildWorld({ domainDocs: false });
  const now = w.clock.now();
  const other: OrgPolicy = { alp: "0.1", id: "other", serial: 1, domains: ["other.example"], updated_at: now.toISOString() };
  const first = join(dir, "other.json");
  const second = join(dir, "example.json");
  const write = (path: string, p: unknown): void => writeFileSync(path, typeof p === "string" ? p : `${JSON.stringify(p, null, 2)}\n`);
  write(first, other);
  write(second, examplePolicy(now));
  const files = PolicyFiles.load([first, second]);
  await w.example.setOrgPolicy({ kind: "admin", operator: "start" }, other);
  const lines: string[] = [];
  const install = (p: OrgPolicy): Promise<void> => w.example.setOrgPolicy({ kind: "admin", operator: "SIGHUP" }, p);
  const send = () => w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Q4", depth: "headline" } });
  assert.equal((await send()).status, "delivered");

  // The kill switch is in the second file; the first didn't change.
  write(second, examplePolicy(now, { serial: 2, blocked: { principals: [ANA] } }));
  assert.deepEqual(await files.reload(install, (l) => lines.push(l)), [{ path: first, result: "unchanged" }, { path: second, result: "installed", serial: 2 }]);
  assert.deepEqual(lines, [`policy ${first}: unchanged`, `policy ${second}: installed serial 2`], "one line per file");
  const blocked = await send();
  assert.equal(blocked.status === "rejected" && blocked.code, "blocked");
  assert.equal(files.policies[1]?.serial, 2, "the server's view of the policies changed too");

  // A file edited without a higher serial keeps its policy; so does one that isn't valid JSON. The next still loads.
  write(first, { ...other, federation: { mode: "deny", domains: ["x.example"] } });
  write(second, "{ not json");
  const stale = await files.reload(install);
  assert.equal(stale[0]?.result, "kept");
  assert.match(stale[0]?.result === "kept" ? stale[0].why : "", /serial 1 isn't higher than 1/);
  assert.equal(stale[1]?.result, "kept");
  assert.match(stale[1]?.result === "kept" ? stale[1].why : "", /isn't a valid policy/);
  assert.equal((await send()).status, "rejected", "the second file's previous policy, with the kill switch, still holds");

  write(first, "{ also not json");
  write(second, examplePolicy(now, { serial: 3 }));
  const recovered = await files.reload(install);
  assert.deepEqual(recovered.map((r) => r.result), ["kept", "installed"], "a malformed first file doesn't stop the second");
  assert.equal((await send()).status, "delivered", "the kill switch is lifted");

  // A file that fails the policy schema is kept too.
  write(second, { ...examplePolicy(now, { serial: 4 }), clients: { mode: "sometimes", allowed: [] } });
  assert.equal((await files.reload(install))[1]?.result, "kept");
  assert.equal(files.policies[1]?.serial, 3);
});
