// SPDX-License-Identifier: FSL-1.1-ALv2
// The organization policy files `npm start` installs, and their reload on SIGHUP (spec 5.8, kill switches). Each file
// is reloaded on its own: one that didn't change is skipped, one that changed without a higher serial is refused, one
// that doesn't parse or fails the schema keeps its previous policy, and the rest still load, so a kill switch in a later
// file applies even when an earlier file didn't change. One result line per file.

import { readFileSync } from "node:fs";
import { refuseUnconnectedDlpHook } from "./core/policy/dlp.ts";
import { checkOrgPolicy } from "./core/policy/org-policy.ts";
import type { OrgPolicy } from "./core/types.ts";

export type ReloadResult =
  | { path: string; result: "unchanged" }
  | { path: string; result: "installed"; serial: number }
  | { path: string; result: "kept"; why: string };

/** A policy file's text as a checked policy (the schema, then the outside-DLP guard). Throws with the reason. */
export function parsePolicy(text: string, path: string): OrgPolicy {
  return refuseUnconnectedDlpHook(checkOrgPolicy(JSON.parse(text)), path);
}

export class PolicyFiles {
  /** The installed policies, in file order: the array `npm start` hands the server (it changes in place). */
  readonly policies: OrgPolicy[];
  private readonly paths: string[];
  private readonly texts: string[];
  private readonly read: (path: string) => string;

  private constructor(paths: string[], texts: string[], policies: OrgPolicy[], read: (path: string) => string) {
    this.paths = paths;
    this.texts = texts;
    this.policies = policies;
    this.read = read;
  }

  /** Reads and checks every file; at startup any problem stops the broker. */
  static load(paths: readonly string[], read: (path: string) => string = (p) => readFileSync(p, "utf8")): PolicyFiles {
    const texts = paths.map((p) => read(p));
    return new PolicyFiles([...paths], texts, texts.map((t, i) => parsePolicy(t, paths[i] ?? "")), read);
  }

  /**
   * Re-reads every file and installs each changed one through `install` (Broker.setOrgPolicy). Never throws: a file
   * that can't be installed keeps its previous policy, and the others still load.
   */
  async reload(install: (policy: OrgPolicy) => Promise<void>, log: (line: string) => void = () => undefined): Promise<ReloadResult[]> {
    const out: ReloadResult[] = [];
    for (const [i, path] of this.paths.entries()) {
      const r = await this.reloadOne(i, path, install);
      out.push(r);
      log(r.result === "unchanged" ? `policy ${path}: unchanged` : r.result === "installed" ? `policy ${path}: installed serial ${r.serial}` : `policy ${path}: kept the previous policy (${r.why})`);
    }
    return out;
  }

  private async reloadOne(i: number, path: string, install: (policy: OrgPolicy) => Promise<void>): Promise<ReloadResult> {
    const current = this.policies[i];
    let text: string;
    try {
      text = this.read(path);
    } catch (err) {
      return { path, result: "kept", why: `can't read it: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (text === this.texts[i]) return { path, result: "unchanged" };
    let next: OrgPolicy;
    try {
      next = parsePolicy(text, path);
    } catch (err) {
      return { path, result: "kept", why: `it isn't a valid policy: ${(err instanceof Error ? err.message : String(err)).slice(0, 300)}` };
    }
    if (current && next.serial <= current.serial) return { path, result: "kept", why: `it changed, but its serial ${next.serial} isn't higher than ${current.serial}` };
    try {
      await install(next);
    } catch (err) {
      return { path, result: "kept", why: (err instanceof Error ? err.message : String(err)).slice(0, 300) };
    }
    this.policies[i] = next;
    this.texts[i] = text;
    return { path, result: "installed", serial: next.serial };
  }
}
