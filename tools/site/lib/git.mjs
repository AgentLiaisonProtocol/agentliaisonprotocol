// Git facts the site shows: when a source last changed, and a file as it was at a commit. When git or the
// history is missing, these return null and the site leaves the fact out rather than guess.

import { execFileSync } from "node:child_process";

function git(root, args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024, timeout: 60_000 });
  } catch {
    return null;
  }
}

/** The committer date (YYYY-MM-DD) of the last commit that changed `path`, or null. */
export function lastChanged(root, path) {
  const out = git(root, ["log", "-1", "--format=%cs", "--", path]);
  return out && /^\d{4}-\d{2}-\d{2}$/.test(out.trim()) ? out.trim() : null;
}

/** The committer date (YYYY-MM-DD) of a commit, or null. */
export function commitDate(root, commit) {
  const out = git(root, ["log", "-1", "--format=%cs", commit]);
  return out && /^\d{4}-\d{2}-\d{2}$/.test(out.trim()) ? out.trim() : null;
}

/** A file's text at a commit, or null when git or the commit is missing. */
export function showAt(root, commit, path) {
  return git(root, ["show", `${commit}:${path}`]);
}

/** Every file and folder path at a commit (a Set), or null. */
export function treeAt(root, commit) {
  const out = git(root, ["ls-tree", "-r", "-t", "--name-only", commit]);
  return out === null ? null : new Set(out.split("\n").filter(Boolean));
}
