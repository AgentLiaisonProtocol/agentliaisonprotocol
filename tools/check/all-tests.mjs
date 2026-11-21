// Loads every test file in test/, so that `node --test tools/check` (from the repository root) and `npm test`
// (from tools/check) run the same tests. Node runs a directory argument as a module; package.json names this file.
import fs from "node:fs";

const dir = new URL("./test/", import.meta.url);
for (const name of fs.readdirSync(dir).filter((n) => n.endsWith(".test.mjs")).sort()) await import(new URL(name, dir));
