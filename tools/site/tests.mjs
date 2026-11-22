// Entry for `node --test tools/site` from the repository root: Node treats a folder argument as a module
// and loads the "main" of its package.json, which is this file. It imports every test in test/.
// (Inside tools/site, `npm test` runs `node --test`, which finds the same files by itself.)
// A file that fails to load (a syntax error, a missing import) is reported as a failing test named after
// the file, and the other files still run.
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "test");
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".test.mjs")).sort()) {
  try {
    await import(pathToFileURL(path.join(dir, f)).href);
  } catch (e) {
    test(`test/${f} loads`, () => {
      throw new Error(`test/${f} could not be loaded: ${e && e.message ? e.message : e}`);
    });
  }
}
