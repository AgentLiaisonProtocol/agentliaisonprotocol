# Running your own broker

The Agent Liaison Protocol (ALP) reference broker in [`reference/`](reference/) runs every deployment profile with the same code: an organization's own broker for its people (the Local profile, the default), a broker that federates with other domains, and a hosted broker. This page shows how to run it yourself, and what isn't built yet. Its license, FSL-1.1-ALv2 ([reference/LICENSE.md](reference/LICENSE.md)), lets any organization use, modify and run it for itself, but not make it available to others in a commercial product or service that substitutes for it or offers substantially similar functionality (the [README](README.md#license) quotes the terms).

**Status: evaluation.** The broker implements the specification's Core requirements that the conformance vectors cover, and passes every vector in [`vectors/`](vectors/); [reference/ARCHITECTURE.md](reference/ARCHITECTURE.md#not-built-yet-and-where-it-goes) lists what it doesn't implement yet, such as push, SCIM and the signed ledger export (spec Section 11.7). People sign in either with test identities from your configuration, each with its own sign-in secret, or through your organization's OpenID provider, such as Microsoft Entra ID ([below](#sign-in-through-your-identity-provider)). That sign-in is built and tested against a standard OIDC provider, and was tested once against a live Entra tenant with test users ([below](#tested-against-a-live-entra-tenant)). One piece a production deployment needs is not built yet:

1. **The person's web view behind your single sign-on, on an address your people can reach.** By default it listens on loopback only, which suits an evaluation on one machine; with OIDC sign-in, each approval there already asks for a fresh sign-in at your provider (a single sign-on step-up). A hosted broker can serve it on its public origin instead (`ALP_WEB_PUBLIC=1`): people sign in by invite and then with a passkey, and every approval needs a fresh passkey check over the hash of the terms (below, "A hosted broker"). Serving it on an HTTPS address behind your organization's single sign-on is not built.

Use test data until you have tested sign-in against your own provider and the web view is in place.

## Evaluate on one machine

To try `npm start` with scripts before any TLS or identity provider is in place, keep the broker's https `id` and call its loopback listener directly over the REST mirror with personal access tokens. Everything stays on 127.0.0.1. Node 22.18 or later:

```sh
cd reference && npm ci
export EVAL="$(mktemp -d)"     # a throwaway directory for the configuration and the data
cp deploy/config.example.json "$EVAL/config.json"
cp deploy/policy.eval.json "$EVAL/"
node -e 'const fs = require("fs"), f = process.argv[1], c = JSON.parse(fs.readFileSync(f, "utf8")); c.policies = ["policy.eval.json"]; fs.writeFileSync(f, JSON.stringify(c, null, 2))' "$EVAL/config.json"
export ALP_CONFIG="$EVAL/config.json" ALP_DATA_DIR="$EVAL/data"
node src/main.ts
```

When it starts, the broker prints one sign-in secret per test person, made for this run (`ALP_DEV_LOGIN_SECRETS` chooses them instead). Note Ana's and Lee's.

[`policy.eval.json`](reference/deploy/policy.eval.json) is the example policy plus two entries in its list of agents: `pat` (personal access tokens, recorded as `self`-attested, `consumer` class) and the public script client of [`clients.example.json`](reference/deploy/clients.example.json). It is for evaluation only. The example policy enforces its list of agents and leaves `pat` out, so with it no script and no personal access token can connect.

1. Open http://127.0.0.1:8081/web, sign in as `ana` with her sign-in secret, and under "Personal access tokens" create a token named `script` with read and send (the form asks for her secret again to confirm). Copy the token; it is shown once. Sign out and do the same for `lee`.
2. In another terminal, call the REST mirror on the loopback listener:

   ```sh
   read -rs ANA; read -rs LEE     # paste Ana's token, Enter, then Lee's, Enter
   alp() { curl -sS "http://127.0.0.1:8080/rest/$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$3"; echo; }
   alp alp_whoami "$ANA" '{}'
   alp alp_send "$ANA" '{"to": "lee@example.org", "scope": "alp.availability/1", "type": "request", "body": {"window": {"start": "2026-11-10T09:00:00Z", "end": "2026-11-10T17:00:00Z"}, "duration_minutes": 30, "timezone": "UTC"}}'
   INBOX="$(alp alp_inbox "$LEE" '{}')"; echo "$INBOX"
   ID="$(printf '%s' "$INBOX" | node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => console.log(JSON.parse(s).items[0].id))')"
   alp alp_ack "$LEE" "{\"ids\": [\"$ID\"]}"
   ```

   On a shared machine, other users can see curl's command line: put the header in a file only you can read and pass `-H @<file>` instead.
3. On each person's page, "Ledger" shows the exchange, and "Export (JSON)" downloads `/web/ledger.json`.
4. Stop the broker with SIGTERM to the node process (Ctrl-C in its terminal sends SIGINT, which stops it the same way), then delete the directory: `rm -rf "$EVAL"`.

An MCP client, such as an agent product's custom connector, follows OAuth discovery from the broker's https `id`, so it needs the broker reachable at that address, with TLS in front ([below](#run-it-with-docker)). The REST calls above skip discovery: a personal access token works on the loopback listener directly.

## Run it with Docker

```sh
git clone https://github.com/AgentLiaisonProtocol/agentliaisonprotocol alp && cd alp
docker build -f reference/Dockerfile -t reference-broker .

cp reference/deploy/config.example.json reference/deploy/policy.example.json /path/to/config/
# edit both: your broker's https origin, your domains, your test identities, your private policy
docker run --rm \
  -e ALP_CONFIG=/config/config.example.json \
  -v /path/to/config:/config:ro \
  -v broker-data:/data \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 \
  reference-broker
```

- **8080** is the public listener: the MCP connector (`/mcp`), the REST mirror (`/rest`), the OAuth authorization server, the connector sign-in page, and, with federation on, the federation inbox and JWKS. Put TLS in front of it (a reverse proxy or a load balancer) at your broker's https origin. When that proxy runs on the same host, publish 8080 on loopback only, as above, so nothing reaches the broker around it; otherwise publish it to the proxy alone.
- **Per-source limits** (failed sign-ins, dynamic registrations, client metadata fetches) key on the connection's address. Behind a reverse proxy every request comes from the proxy, so those limits act as totals, and `npm start` warns when `HOST` is `0.0.0.0` with no client-address header set. Set `ALP_CLIENT_IP_HEADER` to the header your proxy sets (and, for an appended `X-Forwarded-For`, `ALP_TRUSTED_PROXY_HOPS`). Set `ALP_BEHIND_CLOUDFLARE=1` only when the broker is reached solely through Cloudflare (for example a Cloudflare Tunnel), which sets `CF-Connecting-IP` itself; behind any other proxy leave it unset, because any client could send that header.
- **8081** is the person's web view (connection requests, approvals, held messages, the ledger). Publish it on the host's loopback only, as above.
- The broker prints the connector URL and one sign-in secret per test identity; give each only to that person. Set `ALP_DEV_LOGIN_SECRETS` (a JSON object, `{"ana": "...", "lee": "..."}`, at least 12 characters each; `npm start` refuses a shorter one) to choose them. There is deliberately no shared secret: whoever held it could sign in as anyone. With sign-in through your identity provider (`identity.kind: "oidc"`), it prints instead the redirect URIs to register there, and needs `ALP_OIDC_CLIENT_SECRET`.
- State lives in `/data` (file store), or in Postgres with `DATABASE_URL` (below).
- `/healthz` on the public listener answers 200 while the process serves, with the number of security events dropped since start (`{"status": "ok", "security_events_dropped": 0}`); `/readyz` answers 200 when a read of the store succeeds and 503 when it fails. The image's `HEALTHCHECK` calls `/healthz`. The startup banner names the addresses the listeners bind (`HOST:PORT`, `WEB_HOST:WEB_PORT`), each request log line starts with an ISO 8601 UTC timestamp, and `SIGINT` or `SIGTERM` ends with a `stopped` line.
- The image writes security events to standard output, one JSON object per line (`ALP_SECURITY_EVENTS=stdout`), for the container's log driver; set `ALP_SECURITY_EVENTS=file` to keep `security-events.jsonl` in `/data` instead.

Without Docker: Node 22.18 or later, then `cd reference && npm ci && ALP_CONFIG=deploy/config.example.json npm start`.

## Reverse proxy and TLS

Put TLS in front of the public listener at the broker's https `id`. The broker owns the whole origin: every path is its own (`/mcp`, `/rest`, `/oauth`, `/interaction`, `/.well-known`, `/healthz`, `/readyz`, and the federation inbox and JWKS when federation is on), so give it its own host name, with no path prefix. `/mcp` answers each POST with one JSON response: no event stream, no WebSocket, no session id, and GET or DELETE get 405. A proxy needs no sticky sessions, no long timeouts and no buffering changes. Pass the original `Host` header through.

Set `ALP_CLIENT_IP_HEADER` to the header your proxy sets to the client's address, so per-source limits see clients rather than the proxy:

- **nginx** (untested): set the header yourself, so a client can't choose it, and use `ALP_CLIENT_IP_HEADER=x-real-ip`:

  ```nginx
  server {
    listen 443 ssl;
    server_name broker.example.org;
    ssl_certificate     /etc/ssl/broker.example.org.crt;
    ssl_certificate_key /etc/ssl/broker.example.org.key;
    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
    }
  }
  ```

- **Azure Front Door** (untested): `ALP_CLIENT_IP_HEADER=x-azure-socketip`, if every request reaches the broker through Front Door. Microsoft documents `X-Azure-SocketIP` as the address of the TCP connection the request came from, and says that a request's client address can differ from it because the client address "can be arbitrarily overwritten by a user"; so not `X-Azure-ClientIP`: a client could choose its own source. Front Door appends the connection's address to an `X-Forwarded-For` header the request already has, or adds the header, so `ALP_CLIENT_IP_HEADER=x-forwarded-for` with `ALP_TRUSTED_PROXY_HOPS=1` takes the same address. Source: [Protocol support for HTTP headers in Azure Front Door](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol) (Microsoft Learn, updated September 25, 2025; read November 8, 2026).
- **Azure Application Gateway** (untested): `ALP_CLIENT_IP_HEADER=x-forwarded-for`, with `ALP_TRUSTED_PROXY_HOPS` set to the number of proxies that append to it (1 for the gateway alone; 2 with Front Door in front of it, since Front Door appends too). Microsoft documents the gateway's `X-Forwarded-For` header as "a comma-separated list of IP:port": the broker takes the entry that many from the right and drops its port; entries further left were written by the client. Source: [How an application gateway works](https://learn.microsoft.com/en-us/azure/application-gateway/how-application-gateway-works) (Microsoft Learn, updated September 9, 2026; read November 8, 2026).
- **Any other proxy:** a header the proxy sets itself from the connection it received, overwriting whatever the client sent; or an `X-Forwarded-For` it appends to, with `ALP_TRUSTED_PROXY_HOPS`. Never a header a client can send that reaches the broker unchanged.
- **Cloudflare** (a tunnel, or every request proxied through Cloudflare): `ALP_BEHIND_CLOUDFLARE=1`, which reads `CF-Connecting-IP`.

The per-source limits, and what each becomes behind a proxy with no client-address header set (every request then comes from the proxy's address, so each becomes a total for everyone):

| Limit | Per source | Without a client-address header |
|---|---|---|
| Failed connector sign-ins | 10 per source and sign-in name per 15 minutes (100 in all for names that exist) | 10 per sign-in name for everyone |
| Requests to the connector sign-in page | 120 POSTs a minute | 120 a minute for everyone |
| Sign-ins started through your identity provider on the connector page | 30 per 10 minutes | 30 per 10 minutes for everyone |
| Dynamic registrations | 20 an hour (500 registered clients in all) | 20 an hour for everyone |
| Client metadata document fetches | 20 a minute (200 a minute in all; clients your policy lists aren't counted) | 20 a minute for everyone |
| The public web view, on a hosted broker | 120 POSTs a minute, and failed sign-ins per source and name | the same, for everyone |
| The federation inbox | 600 requests a minute per connection address, per instance | always the connection's address: behind a proxy, 600 a minute for all peers together |

Every limit in the table but the federation inbox counts an IPv6 source by its /64, failed sign-ins included, so a client can't spread its tries over the addresses it holds; the federation inbox counts each connection address as it is. On Kubernetes (untested), the image binds the web view to `0.0.0.0` (`WEB_HOST`) so that a host port can reach it: add a NetworkPolicy that admits nothing to port 8081, and reach it with `kubectl port-forward` (it answers only to loopback host names).

## Configure it

`config.json` (see [`reference/deploy/config.example.json`](reference/deploy/config.example.json)):

| Field | Meaning |
|---|---|
| `id` | Your broker's https origin. It is its id in envelopes, its OAuth issuer and its public URL. `npm start` refuses an `id` that isn't https; to evaluate without TLS, see [Evaluate on one machine](#evaluate-on-one-machine). |
| `domains` | The domains whose people it serves. |
| `policies` | Your organization's private policy files ([example](reference/deploy/policy.example.json); schema `schemas/org-policy.schema.json`). Never publish them. |
| `identity` | `{ "kind": "dev", "identities": [...] }` (test identities, one secret each), `{ "kind": "invites" }` (people you invite one by one with `npm run invite`, each with their own secret and then a passkey; for a hosted broker, so it needs `DATABASE_URL` and `web.public`, and `npm start` refuses it without them), or `{ "kind": "oidc", ... }` for your organization's OpenID provider ([below](#sign-in-through-your-identity-provider)). The example file's `identity_examples` holds a generic block and two Entra blocks to copy into `identity`; the broker never reads `identity_examples`. |
| `web` | Optional. `{ "public": true }` serves the person's web view on the broker's public origin (needs `identity.kind` `"invites"`); default: loopback only. |
| `federation` | `false` (default): the Local profile, no domain document needed. `true`: serves the federation inbox and discovers other domains over HTTPS. |

Environment: `PORT`, `HOST`, `WEB_PORT`, `WEB_HOST`, `DATABASE_URL`, `ALP_DB_SCHEMA`, `ALP_DB_POOL_MAX`, `ALP_KEYRING_KEY`, `ALP_OAUTH_KEYS`, `ALP_WEB_PUBLIC`, `ALP_DATA_DIR`, `ALP_SECURITY_EVENTS`, `ALP_DEV_LOGIN_SECRETS`, `ALP_OIDC_CLIENT_SECRET` (the broker's client secret at your identity provider; never in the configuration file), `ALP_REDIRECT_HOSTS` (OAuth redirect hosts besides loopback; default `claude.ai,chatgpt.com`), `ALP_CLIENTS_FILE` (pre-registered OAuth clients: [below](#pre-registered-clients)), `ALP_DCR_REQUIRE_APPLICATION_TYPE`, `ALP_ACCESS_TOKEN_TTL` (access token lifetime in seconds, 60 to 900; default 600), `ALP_BEHIND_CLOUDFLARE` (above), `ALP_CLIENT_IP_HEADER` (the client-address header a hosting platform or proxy sets, such as `x-real-ip` on Vercel; only when every request comes through it), `ALP_TRUSTED_PROXY_HOPS` (of a list-valued `ALP_CLIENT_IP_HEADER` such as `X-Forwarded-For`, the entry this many from the right is the client's: the number of proxies in front that append to it; default 1, the right-most), `ALP_REQUEST_SIGNATURES` (`verify`, the default, accepts unsigned federation requests and refuses a signature that fails; `require` refuses unsigned ones), `ALP_PID_FILE` (where to write the node process's id, for a policy reload), and `ALP_DEFAULT_RATE_LIMIT` and `ALP_OWN_AGENT_RATE_LIMIT` ([below](#rate-limits)). The header of [`reference/src/main.ts`](reference/src/main.ts) describes each.

Before it listens, `npm start` also warns when `DATABASE_URL` is set without `ALP_KEYRING_KEY` (the signing keys are then stored unsealed in the database) and when a policy sets `retention.ledger_days` (recorded, not enforced: nothing is purged).

**Your policy decides the important things:** which agent products may connect (`clients`, in `enforce` mode), which groups may send which typed requests to which (`default_relationships`), which labels stay inside (`classification`), DLP, retention, and the kill switches (`blocked`). DLP here is the reference's sample check (payment cards, private keys, credentials, US SSNs): `npm start` connects no outside DLP service, and refuses a policy whose `dlp.hook` names one. To use yours, implement `DlpHook` ([`reference/src/core/policy/dlp.ts`](reference/src/core/policy/dlp.ts)) and pass it to the `Broker` in `reference/src/main.ts`. Change the policy by editing its file with a higher `serial`, then send the broker's node process `SIGHUP` ([below](#reloading-the-policy)) or restart it; the new policy applies to the next request. A kill switch on a principal, a client or an agent stops its reads, deliveries, tokens and token refreshes as well as its sends; one on a scope or an outside domain stops new messages, while messages already delivered stay readable. In `enforce` mode, removing a client from `clients` cuts off agents already connected with it, and leaving `pat` out forbids personal access tokens, those already issued included. Lowering a client's `attestation` or `class` applies at once to agents already connected; raising it applies at their next sign-in.

### Reloading the policy

On `SIGHUP` the broker reads each policy file again, on its own: a file that didn't change is skipped; a changed file is installed if its `serial` is higher; a changed file whose `serial` wasn't raised, or one that isn't a valid policy, keeps the previous policy; and the other files load either way, so a kill switch in one file applies whatever happened to the others. It logs one line per file (`policy <path>: unchanged`, `installed serial <n>`, or `kept the previous policy (<why>)`): check them after every reload.

The signal must reach the node process. `npm start` runs node as a child process and doesn't pass `SIGHUP` on, so run `node src/main.ts` (from `reference/`) wherever you need to reload; the Docker image does (`docker kill --signal=HUP <container>`). Set `ALP_PID_FILE` to have the broker write its process id to a file, for `kill -HUP "$(cat <file>)"`. With several instances, each needs its own signal. A systemd unit, for example (untested), saved as `/etc/systemd/system/alp.service`:

```ini
[Unit]
Description=ALP reference broker
After=network-online.target

[Service]
User=alp
WorkingDirectory=/opt/alp/reference
Environment=ALP_CONFIG=/etc/alp/config.json ALP_DATA_DIR=/var/lib/alp
EnvironmentFile=/etc/alp/secrets.env
ExecStart=/usr/bin/node src/main.ts
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then `systemctl reload alp` reloads the policy files, and `systemctl stop alp` sends `SIGTERM`, which lets the broker finish the work it had accepted (up to 10 seconds) before it exits.

### Pre-registered clients

`ALP_CLIENTS_FILE` names a JSON file holding an array of OAuth client metadata, in the form the authorization server (oidc-provider) takes: the RFC 7591 names `client_id`, `client_name`, `redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `application_type`, and `client_secret` for a confidential client. The broker reads it once, at startup. [`reference/deploy/clients.example.json`](reference/deploy/clients.example.json) has two: a public script client (`token_endpoint_auth_method` `none`, a loopback redirect URI, `application_type` `native`), and a confidential client for a company workspace agent (`client_secret_post`), whose placeholder secret, marked `REPLACE`, you replace with a long random one. Keep the file out of the repository. Each client also needs:

- an entry in your policy's `clients` (in `enforce` mode, a client the list doesn't name is refused): the example policy lists the confidential one as `org-client`, `enterprise`, which only a client that authenticates at the token endpoint may be (spec Section 5.4);
- for a redirect URI that isn't loopback, its host in `ALP_REDIRECT_HOSTS`.

### Rate limits

Messages are counted in sliding windows. A draft the broker refuses before the limit is checked (a schema or policy refusal) doesn't count; one held for the person's review does.

| Between | Default | Bucket | Set with |
|---|---|---|---|
| Two people, when their terms set no limit | 120 an hour | At the sender's broker, one per sending person and counterparty, shared by all of the person's agents; at the recipient's broker, one per receiving person and sender | `ALP_DEFAULT_RATE_LIMIT`, or `rate_limit` on a default relationship or a grant (when both set one, the stricter applies) |
| One person's own agents | 600 an hour | One per sending agent and receiving agent, in each direction, apart from the person's limits with other people | `ALP_OWN_AGENT_RATE_LIMIT` |

Both variables take `count/seconds`, for example `ALP_OWN_AGENT_RATE_LIMIT=1000/3600` (a count of at most 100,000, over at most 30 days), and `npm start` refuses a value it can't read or that is out of range. A refused message gets `rate_limited` with `retry_after`, the whole seconds until the oldest message in the window leaves it; the REST mirror also sends `Retry-After`. When the recipient's broker refuses with `rate_limited`, its federation inbox answers HTTP 429, with the signed receipt or without one, and the agent is told its `Retry-After`; without one (a receipt carries no wait itself), 30 seconds, the first retry interval of spec Section 10.2.

## Federate with other domains

Turn `federation` on, and the broker prints its entry for your domain document. Publish the document at `https://<your domain>/.well-known/alp.json` (or `https://alp.<your domain>/.well-known/alp.json`), with:

- `brokers`: that entry, with `"principals": "*"` for one broker serving everyone (recommended), or an explicit list;
- `serial`: increase it on every change; `max_age`: 3600 is a good default;
- `security_contact`: a `mailto:` or `https:` contact.

The spec's Section 4 has the rules. Peers pick up changes within `max_age`; an optional TXT record `_alp.<your domain>` with `v=ALP1; id=<serial>` hints that a newer document exists.

## Sign-in through your identity provider

Built and tested against a standard OIDC provider, and tested once against a live Microsoft Entra tenant with test users, on November 8, 2026 ([below](#tested-against-a-live-entra-tenant)). The tests run a standard OpenID provider (oidc-provider) in-process as the stand-in for yours: [`reference/src/oauth/oidc.test.ts`](reference/src/oauth/oidc.test.ts).

The broker is the OAuth authorization server that agents register with; agents never register with your identity provider (Entra has no dynamic registration). When a person connects an agent, the broker's sign-in page sends them to your provider with OpenID Connect (the authorization code flow with PKCE, `state` and `nonce`, and a fresh sign-in each time by default), checks the ID token, binds the person, and only then connects the agent. The person's web view signs in the same way, and each approval there asks for a fresh sign-in at your provider (a single sign-on step-up).

**What the broker checks** in the ID token: the signature against your provider's published keys (asymmetric algorithms only), the exact issuer, the broker's client id as the only audience, expiry, the nonce, and `auth_time` when it asked for a fresh sign-in. Discovery, the keys and the token endpoint are fetched under the same rules as federation (https on port 443, public addresses only, no redirects). It binds the person to `iss` + `sub` (Entra: the tenant + `oid`), never to email, `preferred_username` or `upn`, which can change or be reassigned. The address is an alias read from one claim, on a domain you list: when a person's address changes at your provider, they keep their principal; when an address passes to someone else, the newcomer gets a new principal and inherits none of the old one's relationships (spec Section 5.2). Agents connected under an old address connect again.

**Settings** (`identity` with `"kind": "oidc"`; the examples are in [`reference/deploy/config.example.json`](reference/deploy/config.example.json)):

| Setting | Meaning |
|---|---|
| `provider` | `generic` (the default) or `entra` |
| `issuer` | Generic: your provider's issuer, exactly as its ID tokens carry it. Discovery is at `<issuer>/.well-known/openid-configuration`. |
| `tenant` | Entra: your tenant id, or `organizations` for a multi-tenant app |
| `tenants` | Entra: each tenant whose people may sign in, with the domains its people hold addresses on (`{"<tenant-id>": ["example.org"]}`). Required with `organizations`; a single-tenant app defaults to its own tenant and all the broker's domains. Tokens from any other tenant are refused. |
| `authority` | Entra: `https://login.microsoftonline.com` by default (sovereign clouds have their own) |
| `client_id` | The broker's client id at your provider. The secret goes in `ALP_OIDC_CLIENT_SECRET`, never in the file. |
| `client_auth` | `client_secret_basic` (generic default) or `client_secret_post` (Entra default) |
| `scopes` | `openid profile email` by default, plus `offline_access` when `refresh_check` is on. Entra needs `profile`: it sends `oid` and `preferred_username` only with it. |
| `address_claim` | The claim the address comes from: `email` (generic default; only with `email_verified: true`, unless `require_verified_email` is false) or `preferred_username` (Entra default: usually the user principal name, on a domain your tenant verified) |
| `domains` | Generic: the domains its people may hold addresses on (default: all the broker's domains) |
| `group_claims` | Claims whose values your policy's claim-based groups match: `groups` by default, `roles` for Entra |
| `refresh_check` | Re-check each person at your provider whenever their agent's connection refreshes (default `true`; below) |
| `fresh_sign_in` | Ask your provider for a fresh sign-in (`prompt=login`) each time someone connects an agent (default `true`) |
| `allow_guests` | Entra: also sign in guest accounts (default `false`; below) |
| `clock_skew_seconds` | Allowed clock difference, 0 to 300 (default 60) |

`npm start` checks the block before it listens, and refuses an unknown setting, a client secret in the file, a multi-tenant app without `tenants`, Entra `scopes` without `profile`, or an `address_claim` of `sub`, `oid` or `tid`.

**Any OpenID provider:**
1. Register the broker as a confidential web client. Redirect URIs (the broker prints both at startup): `https://<broker origin>/oidc/callback` for connecting agents, and `http://127.0.0.1:<WEB_PORT>/web/oidc/callback` for the web view; post-logout redirect URI `http://127.0.0.1:<WEB_PORT>/web`.
2. Allow the authorization code and refresh token grants, PKCE, and the `openid`, `profile`, `email` and `offline_access` scopes.
3. Make sure ID tokens carry the address claim (`email` with `email_verified`, or the one you name), `auth_time` (the approvals step-up refuses a sign-in without it), and your group claim.
4. Name your groups in the policy by issuer, claim and value: `"staff": { "claim": { "issuer": "<issuer>", "name": "groups", "value": "staff" } }`.

**Microsoft Entra ID** (tested once against a live tenant with test users, [below](#tested-against-a-live-entra-tenant); the portal's names below follow Microsoft Learn as read in November 2026, which changes; check it for the current ones):
1. **App registration** (Microsoft Entra admin center, as at least Application Developer: Entra ID > App registrations > New registration): under Supported account types, "Single tenant only - <your tenant>" for your own tenant (`tenant` is its id, under Entra ID > Overview > Properties > Tenant ID), or "Multiple Entra ID tenants" with `"tenant": "organizations"` and each tenant you accept listed in `tenants`. The app's Overview page shows its Application (client) ID, your `client_id`.
2. **Redirect URIs**, all on the Web platform (the broker is a confidential client: not Single-page application, not Mobile and desktop applications). Add the https one in the portal (Authentication > Add Redirect URI, or Add a platform, > Web): `https://<broker origin>/oidc/callback`. The portal doesn't accept `http` on `127.0.0.1`, so add the web view's two in the app's Manifest, to `web.redirectUris` (an app registered with a personal Microsoft account still shows the older format, where the list is `replyUrlsWithType`): `http://127.0.0.1:<WEB_PORT>/web/oidc/callback`, and `http://127.0.0.1:<WEB_PORT>/web` for sign-out (Entra sends the browser back after sign-out only to a registered redirect URI). Change only `web.redirectUris` in that save: Entra refuses one that changes `redirectUris` and `redirectUriSettings` together. Use the exact `WEB_PORT` the broker prints, and register them again if it changes: Entra documents port-insensitive matching for `localhost` only. Leave the Front-channel logout URL empty (the broker doesn't implement it) and "ID tokens (used for implicit and hybrid flows)" unticked. A redirect URI Entra doesn't know shows AADSTS50011 on its sign-in page.
3. **Certificates & secrets > Client secrets > New client secret:** copy its Value, shown only once, into `ALP_OIDC_CLIENT_SECRET`. A secret lasts at most 24 months (Microsoft recommends under 12, and certificates rather than secrets in production; the reference supports client secrets only). If your tenant's app management policy blocks new secrets (Entra ID > Enterprise apps > Application policies, "Block password addition"), exclude the broker's app from it.
4. **API permissions** (Microsoft Graph, delegated): a new registration already has `User.Read`; add `openid`, `profile`, `email` and `offline_access`. With "Assignment required?" set to Yes (step 13), people can't consent for themselves, so grant tenant-wide admin consent (API permissions > Grant admin consent for <your tenant>); without it, sign-in fails with AADSTS65001 or AADSTS90094. The re-check at refresh uses the refresh token, so no application permission is needed.
5. **Token configuration > Add optional claim > ID:** add `auth_time`, which approvals need (a connector sign-in checks it when present). For `address_claim: "email"`, the `email` scope the broker asks for is enough, but Entra sends `email` only when the account has an email address.
6. **Groups: prefer app roles.** Create roles under App roles > Create app role (the Value, for example `Finance`, is what the `roles` claim carries), and assign people to them under Entra ID > Enterprise apps > the broker's app > Users and groups > Add user/group, choosing the role. Assigning a group rather than each person needs Entra ID P1 or P2, and members of a nested group don't count. If you use group claims instead (Token configuration > Add groups claim), choose "Groups assigned to the application" and set `group_claims` to include `groups`: a person in more groups than Entra puts in a token gets a link to Microsoft Graph instead of the list (the groups overage), and the broker then refuses the sign-in and says to use app roles, rather than signing them in without their groups.
7. **Issuer and binding:** the broker reads `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` (or the `organizations` document), accepts only the issuer `https://login.microsoftonline.com/<tid>/v2.0` of the token's own `tid` from a listed tenant, and binds the tenant (`tid`) and object id (`oid`), never `upn` or email. Its token requests (the code exchange and each refresh) name the scopes again, which Entra's v2.0 token endpoint may require.
8. **Addresses.** A person's address comes from `preferred_username`: usually their user principal name, on a domain your tenant verified. A user you create in the admin center (Entra ID > Users > New user > Create new user) gets one on your tenant's initial domain, the one Microsoft created with the tenant, unless you added and verified your own (Entra ID > Domain names lists both). The broker accepts an address only on a domain listed for the tenant (`tenants`, which for a single-tenant app defaults to the broker's `domains`), so list that domain, or the sign-in is refused (`address_not_allowed`). Before the `@`, an address holds only letters, digits, dots, hyphens and underscores, starting and ending with a letter or digit; a user principal name with anything else (an apostrophe, for example) is refused (`no_address`). Microsoft documents `preferred_username` as changeable: with email as an alternate login ID turned on, it can be the email the person signed in with rather than the user principal name, so their address can differ from one sign-in to the next. The binding (`tid` + `oid`) doesn't change.
9. **Policy groups** name the role by the tenant's issuer, for example `"finance": { "claim": { "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0", "name": "roles", "value": "Finance" } }` (as in [`reference/deploy/policy.example.json`](reference/deploy/policy.example.json)). Such a group holds the people this broker signed in through that issuer, whichever side of a message they are on, so a default relationship between two roles reaches the other person; people on other brokers are in none (fail closed).
10. **Conditional Access** applies at each sign-in: once per agent connection and once per approval. With `refresh_check`, Entra also evaluates it each time the broker redeems the person's refresh token at an agent's refresh (every 10 minutes): a sign-in-frequency or location policy that refuses the broker's refresh ends that agent's connection, and the person connects it again. That hasn't been tried against Entra (the test [below](#tested-against-a-live-entra-tenant) ran on a free tenant); test it in your tenant. Require phishing-resistant MFA for the broker's app. That needs Entra ID P1 (or its trial): a Conditional Access policy for the broker's app with Grant > Require authentication strength > Phishing-resistant MFA. A free tenant has security defaults instead: every user registers Microsoft Authenticator (or another authenticator app) at their first sign-in, for the whole tenant, which isn't phishing-resistant and can't be limited to the broker's app; the sign-in-frequency and location checks above can't be tried there.
11. **Guests** (B2B guests, personal Microsoft accounts, one-time-passcode guests) are refused: their token's `idp` claim names their home provider, and their `preferred_username` is their home account's name, which your tenant doesn't control. `allow_guests: true` lets them in, still only with an address on a domain listed for the tenant. A tenant first created with a personal Microsoft account holds that account as a member signed in by the personal-account service, so the broker is likely to refuse it the same way: test with a user created in the tenant (step 8).
12. **Offboarding.** With `refresh_check` (the default), each refresh of an agent's connection (every 10 minutes) first redeems the broker's own Entra refresh token for that person. When the provider refuses it, the broker revokes that agent's connection at once, its live access tokens included; Entra is expected to refuse once the account is disabled (Entra ID > Users > the user > Account status > Edit, clear Account enabled) or its sessions are revoked (Revoke sessions, on the user's Overview page). A disabled person's connected agents then stop within the access-token lifetime plus a minute at most (10 minutes by default; a refresh within 30 seconds of a successful check, and the exchange of a code issued in the minute before, aren't checked again), counted from when Entra starts refusing: Microsoft says Revoke sessions can take a few minutes, and gives no bound for a disabled account. In the test [below](#tested-against-a-live-entra-tenant), with both done, Entra refused the agent's next refresh (HTTP 400 `invalid_grant`, AADSTS50057), and the connection ended about 8 minutes after the account was disabled. Refresh tokens issued to a confidential client like the broker survive the user's own password change or self-service reset and an administrator's reset in the Azure portal (one in the Entra or Microsoft 365 admin center revokes them), so those end no connection. If the provider can't be reached, is throttling, or refuses the broker's own request rather than the person (an expired client secret, for example), refreshes fail and connections stay until it answers; the broker's log names the provider's error and Entra's `AADSTS` code. Roles assigned or removed at Entra reach the policy at the next refresh, from the ID token Entra returns with it (in the test below, the broker logged no refreshed ID token it had to leave unused; a role change between refreshes wasn't tried); if that token isn't signed (Microsoft's documentation describes it as unsigned), the broker leaves it unused, logs it and keeps the connection, and the person's roles stay as at their last sign-in until they sign in again. Not covered: personal access tokens (leave `pat` off your list of agents to forbid them) and an open web view session (15 minutes idle; approvals need a fresh Entra sign-in anyway). SCIM provisioning isn't built. An administrator can still block a person at once with the policy's `blocked.principals` and a `SIGHUP`.
13. **Who may sign in:** Entra ID > Enterprise apps > All applications > the broker's app > Properties: set "Assignment required?" to Yes and save, then assign the people (or, with P1 or P2, the groups) who may use the broker under Users and groups. Otherwise every account in the tenant can sign in at Entra, guests invited into it included (the broker then refuses guests itself: step 11). With it, anyone not assigned gets AADSTS50105 at Entra, except a Global Administrator, who can sign in whether assigned or not: try the refusal with a user who isn't one.
14. **Client secrets expire.** Before the broker's secret does, add a new secret to the app registration, restart the broker with it in `ALP_OIDC_CLIENT_SECRET`, then delete the old secret. Until the restart, the broker uses the old one. Once a secret has expired, Entra refuses the broker's requests (AADSTS7000222): sign-ins fail, and agents' refreshes fail without their connections being ended, until the broker restarts with a valid secret.
15. **Scripted pollers** (a script that checks an agent's inbox, [bridge-kit/README.md](bridge-kit/README.md#check-the-inbox-without-waking-the-model)): a personal access token works for up to 30 days and isn't re-checked at Entra; an OAuth connection needs a refresh every 10 minutes (each one re-checked at Entra) and a new interactive sign-in within 30 days.
16. **`address_claim: "email"`** with Entra: Entra's `email` claim carries no `email_verified`, so the broker doesn't require it there and trusts the address only on the domains you list for each tenant (`tenants`). Prefer `preferred_username` (step 8).
17. **A new user's first sign-in.** A user you create gets a temporary password, which Entra usually asks them to change at their first sign-in; under security defaults they also register for multi-factor authentication then. The broker's sign-in expires after 10 minutes: if those steps take longer, start again from the broker's page, or have the user sign in once at https://myaccount.microsoft.com first.
18. Later, to let a vendor's broker speak for your staff, you would authorize it through the same issuer (spec Section 19, future work).

**Switching from test identities:** each person's first sign-in through your provider creates a new principal bound to it. If their address belonged to a test identity, that test principal's relationships end (spec Section 5.2).

**Not built yet:** certificate credentials for the broker's own client; fetching an overflowed group list from Microsoft Graph (the sign-in is refused instead); sign-out started by the provider (front-channel or back-channel logout; signing out on the web view does end the provider's session where it offers RP-initiated logout); an identity provider on a private network; more than one provider configuration per broker (an Entra multi-tenant app can list several tenants); this sign-in on a web view served anywhere but loopback (the public web view, `ALP_WEB_PUBLIC`, signs people in by invite and passkey instead).

### Tested against a live Entra tenant

On November 8, 2026, the reference broker, started with `node src/main.ts` (what `npm start` runs) and the file store, with the changes the [CHANGELOG](CHANGELOG.md) lists under "Changed before publication", was tested against a single-tenant Microsoft Entra ID (Free) tenant with test users. Each test user had an app role, Analyst or Leader, and the policy had an organization default relationship from analysts to leaders. The agent was Claude on claude.ai, through a custom connector with Claude's published client identity (`https://claude.ai/oauth/mcp-oauth-client-metadata`, listed in the policy's `clients` as `vendor`, `business`). Everything below passed:

- **Web view sign-in.** A test user, the Leader, signed in to the web view through Entra. The broker bound them to the tenant's issuer and their object id (`tid` + `oid`), took their address from `preferred_username`, and read their app role from the `roles` claim. Entra accepted the loopback redirect URIs (step 2) in the app's manifest, in `web.redirectUris`; a save that changed `redirectUris` and `redirectUriSettings` together was refused.
- **An agent's connection.** Claude on claude.ai connected for the other test user, the Analyst, through Entra sign-in: Entra asked for a fresh sign-in (`prompt=login`), accepted the code exchange naming the scopes, and issued the refresh token the re-check needs.
- **App roles in policy.** The Analyst's agent sent the Leader an `alp.briefing/1` request under the default relationship between the two roles, and it was delivered; an `alp.status/1` request, outside that relationship, was refused (`no_relationship`).
- **Approvals.** Two approvals on the web view, the Analyst's for their agent's connection request and the Leader's for the incoming request, each needed a fresh Entra sign-in (`prompt=login` with `max_age=0`, and a fresh `auth_time`), and each was recorded as `sso-stepup`.
- **The re-check at refresh.** At the agent's first call after its 10-minute access token expired, claude.ai refreshed the token, and the broker first redeemed its Entra refresh token for that person, naming the scopes. Entra accepted it, and the connection continued. The broker logged no refreshed ID token it had to leave unused (it logs any it can't verify), so a role assigned or removed at Entra should reach the policy at the next refresh; no role was changed during the test.
- **Offboarding.** An administrator disabled the user's account and revoked their sessions. At the agent's next refresh, Entra refused (HTTP 400 `invalid_grant`, AADSTS50057, its code for a disabled account), and the broker revoked the agent's connection at once (security events `token_refused` and `token_revoked`). Every call failed after that, and connecting again was refused at Microsoft's own sign-in page. The connection ended about 8 minutes after the account was disabled, within the 10-minute access-token lifetime.

Not tried there: Conditional Access, sign-in frequency and phishing-resistant MFA (these need Entra ID P1); group claims and the groups overage; a role assigned or removed between refreshes; an address change, or a new account on an old address; guests and personal Microsoft accounts; a user not assigned to the app; a multi-tenant app; `client_secret_basic` (the test used `client_secret_post`, the Entra default); sign-out at Entra; and agent products other than Claude on claude.ai. Certificate credentials and SCIM aren't built (above).

## Postgres

Set `DATABASE_URL` and the broker keeps its state in Postgres: its store, the authorization server's state (grants, sessions, codes, refresh tokens, dynamic registrations), OIDC sign-in's transactions and the provider refresh tokens it keeps for the re-check (sealed), personal access tokens, the web view's sessions, invites and passkeys, and the rate and replay windows of sign-in, registration and the web view. With that and the same `ALP_OAUTH_KEYS` on every instance (`npm run hosted-keys -- ./hosted-secrets.json` writes it to a new 0600 file), several instances can serve one broker; without `ALP_OAUTH_KEYS`, each instance makes its own keys in its `ALP_DATA_DIR`, and tokens and cookies from one fail on another. Each instance still keeps its own federation inbox limit per address and its request-signature nonces (envelope replay is checked in Postgres), writes its own security events (a file, or standard output with `ALP_SECURITY_EVENTS=stdout`) and its own notification outbox file. It creates its tables in the schema `broker` (or `ALP_DB_SCHEMA`) and applies [`reference/migrations/`](reference/migrations/) on start, each migration once even when instances start together (`npm run migrate` applies them separately).

No row holds a usable token: refresh tokens, authorization codes and session cookies are kept only under the SHA-256 of their value (migration 005 cleans rows stored before), personal access tokens and web sessions as hashes, and invite secrets as scrypt hashes. A dynamically registered confidential client's `client_secret` is kept as issued; it authenticates that client, not a person. Every table has row-level security on with no policy (migration 004), so roles without BYPASSRLS, such as Supabase's `anon` and `authenticated`, read and write nothing; roles with it (Supabase's `postgres` and `service_role`), superusers and backups read every row. Set `ALP_KEYRING_KEY` (32 random bytes, base64url; `npm run hosted-keys -- ./hosted-secrets.json` makes one) and the broker's signing keys are sealed in the database under that key, which you keep outside it.

Give the broker its own database role, which owns its schema (it creates the schema and its tables on first start), and nothing else in that database. Connect with TLS and check the server's certificate: `sslmode=verify-full` in `DATABASE_URL`, with `NODE_EXTRA_CA_CERTS` set to the file holding your database's CA certificate if Node doesn't already trust it (with `sslmode=require` the driver encrypts but doesn't check the certificate). Each instance opens up to `ALP_DB_POOL_MAX` connections (default 5): keep the sum over all instances, plus migrations and your own tools, under the server's `max_connections`.

`npm test` runs the Postgres suites on PGlite, Postgres compiled to WebAssembly and run inside the test process, so no database server is needed; `ALP_TEST_POSTGRES_URL=postgres://... npm test` runs them against a real database instead.

## Operate it safely

- Expose only the public listener. Keep the web view, and any admin access, off the internet.
- Signing keys live in the store (`keyrings`). In production, keep them in a KMS or HSM, or at least encrypt that table with a key held outside the database (`ALP_KEYRING_KEY` with Postgres).
- Ship the security events (OCSF-mapped, no message values; `security-events.jsonl`, or standard output with `ALP_SECURITY_EVENTS=stdout`) to your SIEM. A refused bearer token is written once per reason and client per minute, with `detail.count` for the rest of that minute. Ledgers are per person, exported by each person from their web view as plain JSON; `npm run verify-ledger -- <export.json> [<other export.json>]` checks an export's hash chain offline and cross-checks two people's exports message by message. An organization-wide ledger feed, the signed export format of spec Section 11.7 and separately encrypted payloads are not built yet.

### Backups and restores

- **File store** (`ALP_DATA_DIR`): `broker/state.json` (principals, relationships, messages, ledgers), `broker/keys.json` (the broker's signing keys), `binding/binding.json` (connections, tokens, sessions) and `binding/oauth-keys.json` (the authorization server's keys), plus `security-events.jsonl` and `outbox.jsonl`. The two keys files hold private keys: store their backups as secrets. Copy the directory while the broker is stopped, or copy `state.json` and `binding.json` as they are (each is replaced whole, by a rename, on every change).
- **Postgres**: `pg_dump --schema=broker` (or your `ALP_DB_SCHEMA`), plus the keys kept outside the database (`ALP_OAUTH_KEYS`, `ALP_KEYRING_KEY`). Without `ALP_KEYRING_KEY`, the dump holds the broker's private signing keys.
- **Test a restore** on another machine with test traffic: restore, start the broker against it, check that people's ledger pages say "Chain: intact" (or run `npm run verify-ledger` on their exports), and that an agent's existing token or a personal access token still answers `alp_whoami`.

Losing the store loses relationships and ledgers; losing the signing keys means new keys, and, with federation on, republishing your domain document.

### Upgrades

Back up first, then stop every instance, run `npm ci` in `reference/` (or pull the new image), and start. Migrations apply on start, in order, each once even when instances start together. They are forward-only: there is no downgrade, so going back means restoring the backup.

### Files, logs and retention

- The file store suits one instance: it rewrites `state.json` on every change, and nothing coordinates two processes. Use Postgres for more than one instance.
- `security-events.jsonl` and `outbox.jsonl` grow without limit. Rotating them by renaming works, because the broker opens each by name for every write.
- Retention isn't enforced: `retention.ledger_days` is recorded, and nothing is purged (`npm start` warns).

### Key rotation and incidents

| What | What to do | What breaks |
|---|---|---|
| `ALP_OAUTH_KEYS` (or `binding/oauth-keys.json`) | Put new signing keys and a new cookie key first and keep every old key after them; keep the old signing keys at least one access-token lifetime (10 minutes by default) and the old cookie key until every connection has refreshed (a provider session is sealed again under the new key only at its next successful re-check). | Nothing, done that way. Dropping the old keys at once ends every access token, and, with identity-provider sign-in, every connection at its next refresh; people connect again. A connector sign-in in progress starts again. |
| `ALP_KEYRING_KEY` | Rotation isn't built: there is no command to re-seal the signing keys under a new key. Keep it in your secret store, and if it leaks, treat the signing keys as exposed (next row). | |
| The broker's federation and request-signing keys | No command yet (`Broker.rotateKeys` exists, but nothing calls it). If they leak: stop federating (`federation: false`) or take the broker out of your domain document until a new deployment has new keys, then publish them. | Peers refuse envelopes signed with keys your document no longer pins. |
| `ALP_OIDC_CLIENT_SECRET` | Add a new secret at the provider, restart the broker with it, delete the old one. | Nothing, done in that order. |
| One person's account is compromised | Add the person to the policy's `blocked.principals` and send `SIGHUP`: their reads, sends, deliveries, tokens and refreshes stop at once. Then, signed in as them on the web view (or by the operator in their stead), disconnect their agents and revoke their personal access tokens, and disable the account at your identity provider. Remove the block when that is done. | That person's agents, until they connect again after the block is lifted. |

### Residual risks

The broker's own limits are per source, with totals behind them. An outsider with many addresses can still fill the total budgets for clients your policy doesn't list (client metadata fetches, 200 a minute) and for dynamic registrations (500 registered clients). Put a rate limit in front of the public listener (your proxy, load balancer or platform firewall), per client address, on `/oauth/`, `/interaction/`, `/mcp` and `/rest/`.

## A hosted broker (Vercel and Supabase): deployment note

A hosted broker signs people in by invite and serves their web view on its public origin. The reference broker's license applies here as to any other deployment: making the broker available to others in a commercial product or service that substitutes for it or offers substantially similar functionality is a Competing Use, which the license doesn't permit ([README](README.md#license)). The reference broker hasn't been deployed as a hosted broker anywhere. [`reference/deploy/VERCEL-SUPABASE.md`](reference/deploy/VERCEL-SUPABASE.md) is a deployment note, for an operator whose use the license permits, for running one on Vercel with a **dedicated Supabase project**; it hasn't been tried on Vercel or against Supabase. It covers the database role, the migrations, the keys held outside the database, deny-by-default row-level security, the environment variables, and the checklist below in detail. The operator statement the spec requires of a hosted broker (Section 13.9) has a template in [`reference/deploy/OPERATOR-STATEMENT.md`](reference/deploy/OPERATOR-STATEMENT.md), with each operator's decisions left open.

Built for it, and tested on PGlite and, on November 8, 2026, against a PostgreSQL 17.10 server (`ALP_TEST_POSTGRES_URL`; `.github/workflows/ci.yml` runs the same suites on Postgres 17), not yet on Supabase: the shared state in Postgres, so any instance with the same `ALP_OAUTH_KEYS` answers any request, with no usable token in the database; the person's web view on the public origin with invites, passkeys and the other protections spec Section 12.5.2 lists; a passkey on the agents' sign-in page too; keys from the environment; row-level security; expiry of unused dynamic registrations; limits keyed on the platform's client-address header (`ALP_CLIENT_IP_HEADER`).

Still needed before a hosted broker invites anyone: a Vercel entry point (today `npm start` listens on a port; until the entry exists, run the same configuration as a container), a run against a disposable Supabase project, an email notifier (notices reach people only on their page today), replacing a lost passkey, timed deletion of payloads, a security review of the new code, and, from its operator, terms, a data processing agreement and the published operator statement. A hosted broker signs people in by invite: sign-in through an organization's identity provider (above) works with the loopback web view and the agents' sign-in page, not yet with the web view on the public origin. Before the URL is shared, add a rate limit in front of the public listener as well: the broker limits dynamic registration, client metadata fetches, failed sign-ins, OIDC sign-ins started and the requests to its sign-in page and web view itself, each per source, but nothing in it caps requests from many addresses together.
