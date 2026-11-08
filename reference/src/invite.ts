// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run invite`: the operator's invitations for a broker that signs people in by invite (identity.kind "invites",
// a hosted broker). It needs the broker's Postgres database: DATABASE_URL (and ALP_DB_SCHEMA), as `npm start` has.
// A running broker sees each change at once there; with the file store it would never see them (the file is read once,
// at start, and the broker's next write would undo them), so this command refuses to run without DATABASE_URL.
//
//   npm run invite -- create <name> <address> [--days 7] [--display "Ana Example"] [--email ana@example.com] [--origin https://broker.example]
//   npm run invite -- list
//   npm run invite -- revoke <invite id>
//
// `create` prints the person's sign-in secret once and stores only its scrypt hash: give it to them yourself, over a
// channel you trust. It starts their first sign-in, after which they create a passkey; the secret alone never signs
// them in again on the web view. `revoke` stops new sign-ins (one already checking the secret is refused too) and ends
// the person's open web sessions; their connected agents keep working until the person disconnects them or the
// organization's policy blocks them.

import { parseArgs } from "node:util";
import type { Store } from "./core/interfaces.ts";
import type { BindingStore } from "./oauth/state.ts";
import { createPostgresStore } from "./storage/postgres.ts";
import { PostgresBindingStore } from "./storage/postgres-binding.ts";
import { createInvite, isLive, revokeInvite } from "./web/invites.ts";

const USAGE = "usage: npm run invite -- create <name> <address> [--days 7] [--display <name>] [--email <address>] | list | revoke <id>";

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { days: { type: "string" }, display: { type: "string" }, email: { type: "string" } } });
  const [command, ...rest] = positionals;
  if (!command || !["create", "list", "revoke"].includes(command)) throw new Error(USAGE);
  const dbUrl = process.env["DATABASE_URL"];
  if (!dbUrl) throw new Error("npm run invite needs the broker's database: set DATABASE_URL (and ALP_DB_SCHEMA if the broker sets it). Invites are for a hosted broker; with the file store a running broker would never see the change.");
  const pg = await createPostgresStore({ url: dbUrl, max: 1, ...(process.env["ALP_DB_SCHEMA"] ? { schema: process.env["ALP_DB_SCHEMA"] } : {}) });
  const store: Store = pg;
  const binding: BindingStore = new PostgresBindingStore(pg.sql);
  const now = new Date();
  try {
    if (command === "create") {
      const [username, address] = rest;
      if (!username || !address) throw new Error(USAGE);
      const { invite, secret } = await createInvite(binding, {
        username,
        address: address.startsWith("alp:") ? address : `alp:${address}`,
        days: values.days ? Number(values.days) : 7,
        ...(values.display ? { display_name: values.display } : {}),
        ...(values.email ? { email: values.email } : {}),
        now,
      });
      console.log([
        `Invited ${invite.username} as ${invite.address.replace(/^alp:/, "")} until ${invite.expires_at} (invite ${invite.id}).`,
        `Sign-in secret, shown once (give it only to that person):`,
        `  ${secret}`,
      ].join("\n"));
    } else if (command === "list") {
      for (const i of await binding.listInvites()) {
        const state = i.revoked_at ? `revoked ${i.revoked_at}` : isLive(i, now) ? `live until ${i.expires_at}` : `expired ${i.expires_at}`;
        console.log(`${i.id}  ${i.username.padEnd(16)} ${i.address.replace(/^alp:/, "").padEnd(32)} ${state}${i.last_used_at ? `, last sign-in ${i.last_used_at}` : ""}`);
      }
    } else {
      const [id] = rest;
      if (!id) throw new Error(USAGE);
      const done = await revokeInvite(binding, id, now, async (address) => (await store.getPrincipal(address))?.principal_id ?? null);
      if (!done) throw new Error(`no invite ${id}`);
      console.log(`Revoked invite ${done.id} (${done.username}): no new sign-ins with it, and their open web sessions ended.`);
    }
  } finally {
    await binding.close();
    await store.close();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
