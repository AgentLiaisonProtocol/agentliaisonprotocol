// SPDX-License-Identifier: FSL-1.1-ALv2
// One strict I-JSON parse (RFC 7493), as acceptance step 0 requires (spec 8.3, 12.2.4): exactly one JSON text,
// no duplicate member names (JSON.parse silently keeps the last one, so a signer and a verifier could disagree on
// what was signed), no lone surrogates, nesting at most 128 deep. Grammar and duplicates are checked by a small
// scanner; the values themselves come from JSON.parse once the text has passed.

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const STRING = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const MAX_DEPTH = 128;

export class StrictJsonError extends Error {
  constructor(message: string) {
    super(`not strict I-JSON: ${message}`);
    this.name = "StrictJsonError";
  }
}

class Scanner {
  private i = 0;
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
  }

  run(): void {
    this.ws();
    this.value(0);
    this.ws();
    if (this.i !== this.text.length) throw new StrictJsonError(`unexpected text at ${this.i}`);
  }

  private ws(): void {
    while (this.i < this.text.length) {
      const c = this.text.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private string(): string {
    STRING.lastIndex = this.i;
    const m = STRING.exec(this.text);
    if (!m) throw new StrictJsonError(`bad string at ${this.i}`);
    this.i += m[0].length;
    const decoded = JSON.parse(m[0]) as string;
    if (LONE_SURROGATE.test(decoded)) throw new StrictJsonError("lone surrogate in a string");
    return decoded;
  }

  private value(depth: number): void {
    if (depth > MAX_DEPTH) throw new StrictJsonError(`nesting deeper than ${MAX_DEPTH}`);
    const c = this.text[this.i];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') {
      this.string();
      return;
    }
    for (const lit of ["true", "false", "null"]) {
      if (this.text.startsWith(lit, this.i)) {
        this.i += lit.length;
        return;
      }
    }
    NUMBER.lastIndex = this.i;
    const m = NUMBER.exec(this.text);
    if (!m) throw new StrictJsonError(`unexpected character at ${this.i}`);
    if (!Number.isFinite(Number(m[0]))) throw new StrictJsonError("number out of range");
    this.i += m[0].length;
  }

  private object(depth: number): void {
    this.i++; // {
    const seen = new Set<string>();
    this.ws();
    if (this.text[this.i] === "}") {
      this.i++;
      return;
    }
    for (;;) {
      this.ws();
      if (this.text[this.i] !== '"') throw new StrictJsonError(`expected a member name at ${this.i}`);
      const name = this.string();
      if (seen.has(name)) throw new StrictJsonError(`duplicate member name ${JSON.stringify(name)}`);
      seen.add(name);
      this.ws();
      if (this.text[this.i] !== ":") throw new StrictJsonError(`expected ':' at ${this.i}`);
      this.i++;
      this.ws();
      this.value(depth + 1);
      this.ws();
      const c = this.text[this.i];
      this.i++;
      if (c === "}") return;
      if (c !== ",") throw new StrictJsonError(`expected ',' or '}' at ${this.i - 1}`);
    }
  }

  private array(depth: number): void {
    this.i++; // [
    this.ws();
    if (this.text[this.i] === "]") {
      this.i++;
      return;
    }
    for (;;) {
      this.ws();
      this.value(depth + 1);
      this.ws();
      const c = this.text[this.i];
      this.i++;
      if (c === "]") return;
      if (c !== ",") throw new StrictJsonError(`expected ',' or ']' at ${this.i - 1}`);
    }
  }
}

/** Parse one strict I-JSON text. Throws StrictJsonError. */
export function parseStrictJson(text: string): unknown {
  new Scanner(text).run();
  return JSON.parse(text) as unknown;
}

/** Decode UTF-8 bytes strictly (invalid sequences are refused, never replaced), then parse strictly. */
export function parseStrictJsonBytes(bytes: Uint8Array): unknown {
  let text: string;
  try {
    // ignoreBOM keeps a leading U+FEFF in the text, so it can be refused below rather than silently dropped.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new StrictJsonError("invalid UTF-8");
  }
  if (text.charCodeAt(0) === 0xfeff) throw new StrictJsonError("byte order mark");
  return parseStrictJson(text);
}
