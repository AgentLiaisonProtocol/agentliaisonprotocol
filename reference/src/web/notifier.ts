// SPDX-License-Identifier: FSL-1.1-ALv2
// The human-fallback notifier for a local or demo broker (spec 12.5.1): it never sends email or SMS.
// Each notification is printed to the operator's console and appended to an outbox file (JSON lines, mode 0600), as
// the email or text it would be. Notifications only notify: broker-generated text and a link to the broker's own web
// view, behind full sign-in; no link, code or reply in them acts.

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { HumanNotification, Notifier } from "../core/interfaces.ts";

export class ConsoleOutboxNotifier implements Notifier {
  readonly sent: HumanNotification[] = [];
  private readonly outboxPath: string | undefined;
  private readonly print: ((line: string) => void) | undefined;

  constructor(opts: { outboxPath?: string; print?: (line: string) => void } = {}) {
    this.outboxPath = opts.outboxPath;
    this.print = opts.print;
    if (this.outboxPath) mkdirSync(dirname(this.outboxPath), { recursive: true, mode: 0o700 });
  }

  async notify(n: HumanNotification): Promise<void> {
    this.sent.push(structuredClone(n));
    if (this.outboxPath) appendFileSync(this.outboxPath, `${JSON.stringify(n)}\n`, { mode: 0o600 });
    this.print?.(
      n.channel === "email"
        ? [`notification (email, not sent: written to the outbox) to ${n.to}`, `  Subject: ${n.subject}`, ...n.text.split("\n").map((l) => `  ${l}`), `  ${n.link}`].join("\n")
        : `notification (SMS, not sent) to ${n.to}: ${n.subject}. ${n.link}`,
    );
  }
}
