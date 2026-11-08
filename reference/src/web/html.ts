// SPDX-License-Identifier: FSL-1.1-ALv2
// Minimal HTML for the broker's own pages (the connector sign-in page and the person's web view).
// Every value is escaped; counterparty strings are rendered as text only (spec 12.5.2). No scripts, no inline
// styles: one same-origin stylesheet, so the pages run under `Content-Security-Policy: default-src 'self'`.

import type { Response } from "express";
import { PROTOCOL } from "../core/protocol.ts";

export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"'`]/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Tagged template that escapes every interpolated value unless it is already Html. */
export class Html {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): Html {
  let out = strings[0] ?? "";
  values.forEach((v, i) => {
    const piece = v instanceof Html ? v.value : Array.isArray(v) ? v.map((x) => (x instanceof Html ? x.value : esc(x))).join("") : esc(v);
    out += piece + (strings[i + 1] ?? "");
  });
  return new Html(out);
}

export const CSS = `
:root{color-scheme:light dark;--fg:#1d1d1f;--muted:#6e6e73;--bg:#fbfbfd;--card:#fff;--line:#d2d2d7;--accent:#0b57d0;--warn:#8a4b00;--warnbg:#fff4e0;--bad:#a50e0e}
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--muted:#a1a1a6;--bg:#111113;--card:#1c1c1f;--line:#3a3a3f;--accent:#8ab4f8;--warn:#ffcf8a;--warnbg:#3a2a10;--bad:#f28b82}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:860px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:8px 0 16px}h2{font-size:17px;margin:28px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.muted{color:var(--muted)}.warn{background:var(--warnbg);color:var(--warn);border-radius:8px;padding:10px 12px;margin:12px 0}
.bad{color:var(--bad)}code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;word-break:break-word;margin:6px 0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}
label{display:block;margin:6px 0}input[type=text],input[type=password],input[type=number],select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);max-width:100%}
button{font:inherit;padding:7px 14px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;margin:4px 6px 4px 0}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}nav a{margin-right:14px}a{color:var(--accent)}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:baseline}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 8px;font-size:12px}
`;

export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
};

/**
 * The web view's headers on a public origin: nothing loads from anywhere but the page's own origin, scripts only from
 * files there (no inline script, Trusted Types required), and the page can't be framed or opened into by another site.
 */
export const PUBLIC_SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "publickey-credentials-create=(self), publickey-credentials-get=(self), camera=(), microphone=(), geolocation=(), payment=(), usb=()",
};

export function sendPage(res: Response, title: string, body: Html, opts: { status?: number; cssHref?: string; extraCsp?: string; scriptHref?: string; headers?: Record<string, string> } = {}): void {
  for (const [k, v] of Object.entries(opts.headers ?? SECURITY_HEADERS)) res.setHeader(k, k === "Content-Security-Policy" && opts.extraCsp ? `${v}; ${opts.extraCsp}` : v);
  res.status(opts.status ?? 200).type("html").send(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>${esc(title)} · ${esc(PROTOCOL.shortName)} broker</title><link rel="stylesheet" href="${esc(opts.cssHref ?? "/static/alp.css")}">` +
      (opts.scriptHref ? `<script src="${esc(opts.scriptHref)}" defer></script>` : "") +
      `</head><body><main>${body.value}</main></body></html>`,
  );
}
