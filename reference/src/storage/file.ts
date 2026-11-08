// SPDX-License-Identifier: FSL-1.1-ALv2
// File-backed Store for local brokers: the memory store, persisted after every change.
// State goes to <dir>/state.json and private keys to <dir>/keys.json (mode 0600), each written to a
// temporary file and renamed into place, so a crash never leaves a half-written file.

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { StoredKeyRing } from "../core/keys.ts";
import { MemoryStore, emptyState } from "./memory.ts";
import type { MemoryState } from "./memory.ts";

function writeAtomic(path: string, data: string, mode: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, path);
}

export class FileStore extends MemoryStore {
  override readonly kind: string = "file";
  readonly dir: string;
  private closed = false;

  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const statePath = join(dir, "state.json");
    const keysPath = join(dir, "keys.json");
    let state: MemoryState = emptyState();
    if (existsSync(statePath)) state = JSON.parse(readFileSync(statePath, "utf8")) as MemoryState;
    if (state.version !== 2) throw new Error(`unsupported store version in ${statePath}`);
    if (existsSync(keysPath)) state.keyrings = JSON.parse(readFileSync(keysPath, "utf8")) as Record<string, StoredKeyRing>;
    super(state);
    this.dir = dir;
  }

  protected override changed(): void {
    if (this.closed) throw new Error("store is closed");
    const { keyrings, ...rest } = this.state;
    writeAtomic(join(this.dir, "state.json"), JSON.stringify({ ...rest, keyrings: {} }), 0o600);
    writeAtomic(join(this.dir, "keys.json"), JSON.stringify(keyrings), 0o600);
  }

  override async close(): Promise<void> {
    this.closed = true;
  }
}
