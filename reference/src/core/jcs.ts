// SPDX-License-Identifier: FSL-1.1-ALv2
// RFC 8785 JSON Canonicalization Scheme (JCS).
// Numbers use the ECMAScript Number-to-String algorithm (what JSON.stringify does for finite numbers),
// strings use ECMAScript JSON string escaping, and object members are sorted by UTF-16 code units.
// Input must be I-JSON (RFC 7493): no lone surrogates, no non-finite numbers.

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class JcsError extends TypeError {
  constructor(message: string) {
    super(`JCS: ${message}`);
    this.name = "JcsError";
  }
}

function serializeString(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new JcsError("string contains a lone surrogate");
  return JSON.stringify(s);
}

function serialize(value: unknown, out: string[], depth: number): void {
  if (depth > 128) throw new JcsError("nesting deeper than 128");
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "number":
      if (!Number.isFinite(value)) throw new JcsError("non-finite number");
      out.push(JSON.stringify(value)); // -0 becomes "0", as RFC 8785 requires
      return;
    case "string":
      out.push(serializeString(value));
      return;
    case "object": {
      if (Array.isArray(value)) {
        out.push("[");
        for (let i = 0; i < value.length; i++) {
          if (i > 0) out.push(",");
          const item: unknown = value[i];
          if (item === undefined) throw new JcsError("undefined inside an array");
          serialize(item, out, depth + 1);
        }
        out.push("]");
        return;
      }
      const proto: unknown = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new JcsError("only plain objects can be canonicalized");
      const record = value as Record<string, unknown>;
      // Members whose value is undefined are absent, as in JSON.stringify.
      const keys = Object.keys(record)
        .filter((k) => record[k] !== undefined)
        .sort();
      out.push("{");
      keys.forEach((k, i) => {
        if (i > 0) out.push(",");
        out.push(serializeString(k));
        out.push(":");
        serialize(record[k], out, depth + 1);
      });
      out.push("}");
      return;
    }
    default:
      throw new JcsError(`cannot canonicalize a ${typeof value}`);
  }
}

/** The RFC 8785 canonical JSON text of `value`. */
export function canonicalize(value: unknown): string {
  const out: string[] = [];
  serialize(value, out, 0);
  return out.join("");
}

/** UTF-8 bytes of the canonical form. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
