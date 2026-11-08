// SPDX-License-Identifier: FSL-1.1-ALv2
// src/web: the person's web view (spec 12.5) and the human-fallback notifier.
// Paths (core/notify.ts webLinks): /web, /web/connections/:id, /web/ratifications/:id, /web/messages/:id, /web/ledger.
// POST-only actions with CSRF tokens and a fresh sign-in for every approval; CSP default-src 'self',
// frame-ancestors 'none'; HttpOnly SameSite=Strict session cookies (__Host- and Secure over HTTPS), 15-minute idle
// timeout; counterparty strings as text only; only the signed-in principal's items. Loopback only during a test through a tunnel.

export { webRouter } from "./app.ts";
export type { WebOptions } from "./app.ts";
export { ConsoleOutboxNotifier } from "./notifier.ts";
export { IDLE_TIMEOUT_MS, WebSessions } from "./sessions.ts";
export type { WebSession } from "./sessions.ts";
export { CSS, Html, SECURITY_HEADERS, esc, html, sendPage } from "./html.ts";
