// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run migrate`: apply the Postgres store's migrations (migrations/*.sql) to DATABASE_URL, then exit.
// `npm start` applies them too; this is for deployments that migrate before starting the broker.

import postgres from "postgres";
import { migrate } from "./postgres.ts";

const url = process.env["DATABASE_URL"];
if (!url) {
  console.error("Set DATABASE_URL (postgres://...).");
  process.exit(2);
}
const schema = process.env["ALP_DB_SCHEMA"] ?? "broker";
const sql = postgres(url, { max: 1, prepare: false, onnotice: () => undefined });
try {
  const applied = await migrate(sql, schema);
  console.log(applied.length ? `Applied migrations ${applied.join(", ")} to schema ${schema}.` : `Schema ${schema} is up to date.`);
} catch (err) {
  console.error(`migration failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
} finally {
  await sql.end({ timeout: 5 });
}
