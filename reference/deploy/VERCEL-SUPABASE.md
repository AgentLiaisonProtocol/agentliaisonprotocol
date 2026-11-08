# Deploy note: a hosted broker on Vercel and a separate Supabase project

How a hosted ALP broker (people signed in by invite, the web view on its public origin) would run on Vercel with its own Supabase project: an example for an operator, within the reference broker's license ([LICENSE.md](../LICENSE.md), FSL-1.1-ALv2), which doesn't permit making it available to others in a commercial product or service that substitutes for it or offers substantially similar functionality. **Nothing has been deployed this way.** This note lists what the reference broker now provides for it, the configuration, and what is still missing. The broker's Postgres code runs on PGlite (Postgres 18 compiled to WebAssembly, in the test process) in `npm test` and on Postgres 17 in CI; it has never run against Supabase or on Vercel. Each `[[DECIDE: ...]]` marks a choice for whoever operates the broker.

## What the broker provides for a hosted deployment

| Need | What the reference does | Tested by |
|---|---|---|
| Any instance answers any request | With `DATABASE_URL`, and the same `ALP_OAUTH_KEYS` on every instance (Section 2), the broker's store, the authorization server's state (grants, sessions, interactions, codes, refresh tokens, dynamic registrations, replay detection), personal access tokens, held connection requests, send idempotency, the web view's sessions, challenges, invites, passkeys and known browsers, and the rate and replay windows of sign-in, registration and the web view are in Postgres. Each instance keeps its own federation inbox limit and request-signature nonces (federation is off in this deployment); security events go to the log (`ALP_SECURITY_EVENTS=stdout`) | `storage/store.test.ts`, `storage/binding-store.test.ts`, and two instances behind one round-robin address in `web/hosted.test.ts` |
| No usable token in the database | Refresh tokens, authorization codes, registration access tokens and session cookies are kept only as the SHA-256 of their value: the adapter leaves oidc-provider's copy of each id (`jti`) out of the stored payload, and migration `005` cleans rows stored before. Personal access tokens and web sessions are kept as hashes, invite secrets as scrypt hashes. One credential is kept as issued: a dynamically registered confidential client's `client_secret` (it authenticates that client, not a person) | `storage/binding-store.test.ts` (on every store), `oauth/oauth.test.ts` (a whole sign-in, exchange and refresh), `storage/hosted-db.test.ts` (migration `005`) |
| A revocation always wins | Revoking an invite or a personal access token writes only its `revoked_at`, and a use is recorded only on a live one, so a sign-in or request already in progress can't write it back live: the sign-in is refused. Of two first passkey registrations at once, one is stored | `storage/binding-store.test.ts`, `web/invites.test.ts` |
| The person's page on the public origin | `ALP_WEB_PUBLIC=1`: sign-in by invite, a passkey before anything else, a fresh passkey check over the hash of the terms for every approval, `__Host-` cookies, CSRF and Origin checks, a strict CSP, the 15-minute idle timeout, a notice on sign-in from a new browser, request and failure limits | `web/hosted.test.ts` |
| The agents' sign-in on the public origin | The connector sign-in page asks for the person's invite secret and then their passkey, over a challenge bound to that authorization | `web/hosted.test.ts` |
| Keys outside the database | `ALP_OAUTH_KEYS` (token and cookie keys) from the environment; `ALP_KEYRING_KEY` seals the broker's protocol signing keys in the database (AES-256-GCM) | `storage/hosted-db.test.ts` |
| Deny by default in the database | Migration `004_row_level_security.sql`: row-level security on every table with no policy; `anon` and `authenticated` lose every grant on the schema | `storage/hosted-db.test.ts` (as `anon`: no access; with the schema granted by mistake, no rows and no writes) |
| Unused registrations don't pile up | A dynamic client registration expires after 30 days without use | `storage/binding-store.test.ts` |
| Safe concurrent start-up | Each migration runs once, under a transaction-level advisory lock (works through Supabase's transaction pooler) | `storage/hosted-db.test.ts` |

Run them with `cd reference && npm ci && npm test` (no database needed). `ALP_TEST_POSTGRES_URL=postgres://...` runs the same Postgres suites against a real database instead; point it at a disposable database, never the broker's own.

## 1. Supabase: a separate project

1. **Create a new Supabase project for the broker only.** Nothing else of the operator's lives in it, and the broker uses nothing of anyone else's. Region: [[DECIDE: Supabase region]], next to the Vercel region below.
2. **Create a database role for the broker** (not `postgres`, never the service-role key; the broker doesn't use Supabase's client libraries or keys at all). In the SQL editor, roughly: `create role alp_broker login password '<generated>'; grant create on database postgres to alp_broker;`. The broker creates the schema `broker` the first time it migrates, and owns it. Check Supabase's current documentation for how a custom role connects through the pooler (the user name format includes the project reference).
3. **`DATABASE_URL`**: the **transaction pooler** connection string (port 6543) for that role, with `sslmode=verify-full`, and `NODE_EXTRA_CA_CERTS` set to the path of the project's CA certificate (from its database settings) if Node doesn't already trust it: with `sslmode=require` the driver encrypts but doesn't check the certificate. The broker turns prepared statements off, as the transaction pooler requires.
4. **Keep the schema out of the Data API.** Don't add `broker` to the API's exposed schemas. If the project serves nothing through the Data API, turn the Data API off in the project's settings.
5. **Migrate before deploying**, from a trusted machine: `cd reference && DATABASE_URL=... npm run migrate`. The broker also migrates when it starts, under a lock, so concurrent cold starts are safe, but migrating first keeps start-up fast and the change deliberate. The migrations are `reference/migrations/001_initial.sql` (the store), `002_binding.sql` (authorization server and tokens), `003_web.sql` (the web view), `004_row_level_security.sql` (deny by default), `005_no_raw_token_ids.sql` (no raw token ids in stored payloads), `006_one_live_principal.sql` (one live principal per address and per identity) and `007_deferred_notices.sql` (notifications that wait for a grant's quiet hours to end).
6. **Check deny by default** in the SQL editor after migrating (read-only):
   ```sql
   -- expect no rows: every table has row-level security on
   select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'broker' and c.relkind = 'r' and not c.relrowsecurity;
   -- expect false, false: the API roles can't even reach the schema
   select has_schema_privilege('anon', 'broker', 'USAGE'), has_schema_privilege('authenticated', 'broker', 'USAGE');
   ```
7. **Backups:** turn on point-in-time recovery if the plan allows. A restore brings back sealed signing keys, which need `ALP_KEYRING_KEY` to open. Row-level security doesn't apply to roles with BYPASSRLS (Supabase's `postgres` and `service_role`), to superusers or to backups and dumps: whoever can read those reads every row, though no row holds a usable token or signing key.

## 2. Keys held outside the database

Generate both secrets on a trusted machine: `cd reference && npm run hosted-keys -- ./hosted-secrets.json`. It writes a new file (mode 0600) and prints nothing secret.

| Variable | What it is | Where it lives |
|---|---|---|
| `ALP_OAUTH_KEYS` | The authorization server's keys: ES256 for access tokens, RS256 for ID tokens, and the cookie keys. Every instance must have the same ones. | Vercel environment variable, marked Sensitive, Production only |
| `ALP_KEYRING_KEY` | 32 random bytes that seal the broker's federation and request-signing keys in the `keyrings` table. Without it, a copy of the database holds no usable signing key; without it, the broker also can't start. | Vercel environment variable, marked Sensitive, Production only |

Copy the two values into Vercel, then delete the file. Neither belongs in the database, the repository or a chat.

To roll `ALP_OAUTH_KEYS` over, make new keys (`npm run hosted-keys -- <new file>`) and put the new signing keys and the new cookie key first, with every old key kept after them: the broker signs with the first key of each kind and checks with all of them. Keep the old signing keys for at least one access-token lifetime (`ALP_ACCESS_TOKEN_TTL`, 10 minutes by default), so access tokens already issued still verify. Keep the old cookie key until every connection has refreshed: with sign-in through an organization's identity provider, the provider session behind each connection is sealed under the first cookie key, and it is sealed again under the new one only at its next successful re-check; dropping the old key before then ends those connections at their next refresh. A connector sign-in in progress during the switch starts again. Agents keep their refresh tokens: those are random values the database knows only by their hash, not tokens signed with these keys. Replacing the keys outright, keeping none of the old ones, invalidates the access tokens already issued and, with identity-provider sign-in, ends every connection at its next refresh. Rotating `ALP_KEYRING_KEY` (re-sealing under a new key) isn't built yet. Refresh tokens, codes, invite secrets and session ids are stored only as hashes, so they need no key.

## 3. Vercel

### Environment variables (names only)

| Name | Value |
|---|---|
| `DATABASE_URL` | the Supabase transaction pooler string for `alp_broker` (Section 1) |
| `ALP_KEYRING_KEY`, `ALP_OAUTH_KEYS` | Section 2 |
| `ALP_CONFIG` | path of the broker's configuration in the deployment: `identity.kind` `"invites"`, `web.public` `true`, `federation` `false`, its own domain and policy |
| `ALP_WEB_PUBLIC` | `1` (or `web.public` in the configuration) |
| `ALP_SECURITY_EVENTS` | `stdout`: security events go to Vercel's logs and any log drain |
| `ALP_DATA_DIR` | `/tmp/alp` (Vercel's only writable place; it holds nothing the broker needs to keep) |
| `ALP_CLIENT_IP_HEADER` | the header Vercel sets to the client's address (`x-real-ip`; check Vercel's current header documentation), so per-source limits don't treat every visitor as one |
| `ALP_DB_POOL_MAX` | `1` or `2`: many short-lived instances each hold this many connections |
| `ALP_DB_SCHEMA` | unset (default `broker`) |
| `ALP_SCHEMA_DIR` | where the bundled `schemas/` directory sits in the function, if not next to the code |
| `ALP_REDIRECT_HOSTS`, `ALP_CLIENTS_FILE`, `ALP_ACCESS_TOKEN_TTL` | optional, as in `SELF-HOST.md` |

Don't set `ALP_DEV_LOGIN_SECRETS` (a hosted broker signs people in by invite) or `ALP_BEHIND_CLOUDFLARE` (Vercel isn't Cloudflare).

### The project

- **Node 22**, the repository root as the project root: the broker reads `schemas/` and `reference/migrations/` at run time, so both must be in the function's bundle (`includeFiles` in `vercel.json`).
- **Region:** [[DECIDE: Vercel function region]], the same as the Supabase project's.
- **One production domain:** [[DECIDE: the broker's domain]]. It is the broker's `id` and its OAuth issuer. The web view answers only to that host name, so preview deployments (other host names) can't serve it; turn preview deployments off for this project, or protect them.
- **A rate limit in front:** a Vercel Firewall rule for `/oauth/*`, `/interaction/*`, `/web/login` and `/mcp` per client address, on top of the broker's own limits. The broker's limits are per source (the connector sign-in page and the web view each take 120 requests a minute from one address, an IPv6 /64 counting as one address); nothing in the broker caps requests from many addresses together, so this rule is the layer for that.
- **The entry point (not built).** `npm start` listens on a port, as a container does. On Vercel the broker needs a function entry that builds it once per instance (the store, the keys, the configuration) and exports the HTTP app. The remaining code change is to split `startBrokerServer` (`reference/src/server.ts`) into building the app and listening; then the entry is a few lines. Until that entry exists and has been tried on a Vercel preview with a disposable Supabase project, run the same configuration as a container (`reference/Dockerfile`) on any host with a persistent process and TLS in front; everything above applies there too. The proxy in front must pass the original `Host` header through (the web view answers only to the broker's own host name), and `ALP_CLIENT_IP_HEADER` should name the header that proxy sets to the client's address.
- **Work after the answer.** For an accepted message the broker notifies the person and pushes to agents after it has answered (spec 6.7), through the `background` option of `Broker` (by default the next turn of the event loop); a hold is already in the ledger by then. A function instance may be frozen or stopped once its response is sent, which would drop that work without a trace: the entry must pass a `background` that keeps the instance alive until the task settles and still runs it after the answer (for example `(task) => waitUntil(new Promise((next) => setImmediate(next)).then(task))` with Vercel's `waitUntil`, which the broker calls while the request is still being handled), and an `onBackgroundError` that writes to the function's log.
- **Notifications that wait for quiet hours.** A long-running broker sends the notifications that waited for a grant's quiet hours to end within a minute of it (`startBrokerServer` starts `Broker.startNoticeTimer`). A function instance runs only while it handles a request, so the entry must also call `broker.sendDueNotices()` on a schedule, for example from a Vercel Cron Job that requests a route the entry protects with a secret. Of several instances, each due notification goes to one (`takeDueNotices`).

### What runs per instance, and what doesn't need to

Everything that must be shared is in Postgres. Each instance still keeps a few things of its own, which is safe: oidc-provider's cache of client metadata documents; the domain-document cache, the federation inbox's per-address limit and its request-signature nonces (federation is off in this deployment; envelope replay is checked in Postgres); and the organization-or-not flag for a connection's lifetime, which falls back to the shorter organization limit (30 days) on an instance that hasn't seen the account.

## 4. Inviting people

From a trusted machine with `DATABASE_URL` set to the broker's database (the command refuses to run without it: invites reach a running broker only through Postgres, so `npm start` also refuses `identity.kind` `"invites"` without `DATABASE_URL` and the public web view):

```sh
cd reference
npm run invite -- create ana ana@<broker domain> --display "Ana Example" --email ana@example.com --days 7
npm run invite -- list
npm run invite -- revoke <invite id>
```

`create` prints the person's secret once; deliver it yourself, over a channel you trust, and never in the same message as the link. Whoever uses the secret first registers the passkey (a second registration is refused, even one at the same moment, and each person's page lists their passkeys), so if someone says they couldn't create theirs, revoke the invite and look before inviting again. The person signs in at `https://<broker domain>/web`, creates a passkey at once, and then connects agents with the connector URL `https://<broker domain>/mcp`. `revoke` stops new sign-ins (a sign-in checking the secret at that moment is refused too) and ends the person's open web sessions; their connected agents keep working until the person disconnects them or the policy blocks them.

## 5. Before anyone is invited

Built in the reference, and tested on PGlite and, on November 8, 2026, against a PostgreSQL 17.10 server (`ALP_TEST_POSTGRES_URL`; `.github/workflows/ci.yml` runs the same suites on Postgres 17), never on Supabase: everything in the first table.

Still needed:
- [ ] The Vercel entry point and bundling (Section 3), tried on a Vercel preview with a disposable Supabase project; and the Postgres suites run once against that disposable project (`ALP_TEST_POSTGRES_URL`).
- [ ] An email notifier. The reference's notifier writes notices (connection requests, sign-in from a new browser) to the log and an outbox file; nobody receives them by email. Until one is built, people see them only on their page.
- [ ] A way to replace a lost passkey. Today the operator would have to delete the person's passkeys in the database and send a new invite.
- [ ] Timed deletion of payloads for the retention the operator statement promises.
- [ ] Rotation of `ALP_KEYRING_KEY`.
- [ ] A security review of the new sign-in, passkey and Postgres code.
- [ ] Terms, a data processing agreement, and the operator statement (`OPERATOR-STATEMENT.md`) with every `[[DECIDE: ...]]` filled in and published.

Not needed for this deployment: sign-in through an identity provider. It is built (`identity.kind` `"oidc"`, SELF-HOST.md), but only with the web view on loopback; a hosted broker signs people in by invite on the public origin.
