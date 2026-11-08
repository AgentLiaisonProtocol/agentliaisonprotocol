// SPDX-License-Identifier: FSL-1.1-ALv2
import type { HumanNotification, LinkBuilder, Notifier } from "./interfaces.ts";

/** Links into the broker's own web view. No personal data in the URL; the page requires full sign-in. */
export function webLinks(webBaseUrl: string): LinkBuilder {
  const base = webBaseUrl.replace(/\/+$/, "");
  return {
    connection: (id) => `${base}/connections/${encodeURIComponent(id)}`,
    ratification: (id) => `${base}/ratifications/${encodeURIComponent(id)}`,
    message: (id) => `${base}/messages/${encodeURIComponent(id)}`,
    held: (id) => `${base}/held/${encodeURIComponent(id)}`,
    ledger: () => `${base}/ledger`,
  };
}

/** Keeps every notification (tests, the demo) and optionally prints it as the email or text it would be. */
export class RecordingNotifier implements Notifier {
  readonly sent: HumanNotification[] = [];
  private readonly print: ((text: string) => void) | undefined;

  constructor(opts: { print?: (text: string) => void } = {}) {
    this.print = opts.print;
  }

  async notify(n: HumanNotification): Promise<void> {
    this.sent.push(structuredClone(n));
    if (!this.print) return;
    if (n.channel === "email") {
      this.print([`  To: ${n.to}`, `  Subject: ${n.subject}`, "", ...n.text.split("\n").map((l) => `  ${l}`), "", `  ${n.link}`].join("\n"));
    } else {
      this.print(`  SMS to ${n.to}: ${n.subject}. ${n.link}`);
    }
  }
}
