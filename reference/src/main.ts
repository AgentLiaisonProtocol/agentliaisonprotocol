// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm start`: a configured broker for self-hosting (SELF-HOST.md) and hosted deployments. The same code as the
// demo and `npm run dev`, set up from a JSON file and the environment instead of the development world.
//
// Environment:
//   ALP_CONFIG            path of the JSON configuration (required; see config.example.json)
//   PORT, HOST           the public listener: MCP, REST, OAuth, the sign-in page, and the federation inbox and JWKS
//                        when federation is on (default 8080 on 127.0.0.1; 0.0.0.0 inside a container)
//   WEB_PORT, WEB_HOST   the person's web view (default 8081 on 127.0.0.1); it answers only to loopback host names
//   DATABASE_URL         Postgres (hosted): the broker's store, the client binding's state (OAuth grants, sessions,
//                        tokens, invites, passkeys) and the rate and replay windows (all but the federation inbox's
//                        per-address limit and request-signature nonces, which stay per instance); without it, files
//                        in ALP_DATA_DIR. Several instances can serve one broker with it and the same ALP_OAUTH_KEYS.
//   ALP_DB_SCHEMA         Postgres schema (default broker)
//   ALP_KEYRING_KEY       with DATABASE_URL: 32 random bytes (base64url) that seal the broker's signing keys in the
//                        database (AES-256-GCM). Keep it outside the database. `npm run hosted-keys -- <new file>`
//                        writes one to a new 0600 file.
//   ALP_OAUTH_KEYS        the authorization server's keys as JSON (`npm run hosted-keys -- <new file>`), so every instance signs and
//                        checks tokens and cookies alike; default: oauth-keys.json in ALP_DATA_DIR (one instance only)
//   ALP_ACCESS_TOKEN_TTL  access token lifetime in seconds (default 600; 60 to 900)
//   ALP_WEB_PUBLIC        1 serves the person's web view on the public origin (a hosted broker), behind invites and
//                        passkeys (identity.kind "invites", which needs it and DATABASE_URL); default: loopback only
//   ALP_SECURITY_EVENTS   "file" (the default; security-events.jsonl in ALP_DATA_DIR) or "stdout" (one JSON object per
//                        line on standard output, for a platform's log drain; the Docker image's default)
//   ALP_CLIENT_IP_HEADER  the header the hosting platform or proxy sets to the client's address (e.g. x-real-ip on
//                        Vercel or behind nginx), for per-source limits; only when every request comes through it
//   ALP_TRUSTED_PROXY_HOPS  of a list-valued ALP_CLIENT_IP_HEADER (X-Forwarded-For), the entry this many from the right
//                        is the client's: the number of proxies in front that append to it (default 1, the right-most)
//   ALP_DB_POOL_MAX       Postgres connections per instance (default 5; 1 or 2 suits many short-lived instances)
//   ALP_DATA_DIR          file store, authorization-server state, outbox and security events (default ./.data/broker)
//   ALP_DEV_LOGIN_SECRETS identity.kind "dev": a JSON object of per-identity sign-in secrets ({"ana": "...", "lee": "..."}),
//                        each at least 12 characters (a shorter one is refused); identities without one get a generated
//                        secret, printed once. Each person signs in only as
//                        themselves: a single shared secret would let anyone who holds it act as anyone (spec 5.3).
//   ALP_OIDC_CLIENT_SECRET identity.kind "oidc": the broker's client secret at the organization's identity provider
//                        (required; never in the configuration file, never printed)
//   ALP_REDIRECT_HOSTS    OAuth redirect hosts besides loopback (default claude.ai,chatgpt.com)
//   ALP_CLIENTS_FILE      pre-registered OAuth clients: a JSON array of oidc-provider client metadata (RFC 7591 names),
//                        read once at startup (deploy/clients.example.json; SELF-HOST.md, "Pre-registered clients")
//   ALP_DCR_REQUIRE_APPLICATION_TYPE  0 accepts dynamic registrations without application_type
//   ALP_BEHIND_CLOUDFLARE 1 when the public listener is reached only through Cloudflare (a tunnel): per-source limits
//                        then use Cloudflare's CF-Connecting-IP. Leave it unset behind any other proxy.
//   ALP_REQUEST_SIGNATURES  federation inbox: "verify" (default; unsigned requests are accepted, a signature that
//                        fails is refused) or "require" (every request must carry a valid RFC 9421 signature)
//   ALP_DEFAULT_RATE_LIMIT  messages between two people when their terms set none, as count/seconds (default
//                        120/3600): one bucket per sending person and counterparty at the sender's broker, and per
//                        receiving person and sender at the recipient's
//   ALP_OWN_AGENT_RATE_LIMIT  messages between one person's own agents, as count/seconds (default 600/3600): one
//                        bucket per sending agent and receiving agent, apart from the person's limits with others
//   ALP_PID_FILE          write this node process's id to the file, for `kill -HUP $(cat <file>)` (policy reload)
//   ALP_DEV_HOSTS         development only: a JSON map of origins to http://127.0.0.1:<port> for local federation tests
//                        (and for a local stand-in identity provider); never in production

import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { Broker } from "./core/broker.ts";
import { DEV_ISSUER, DevIdentityVerifier } from "./core/identity.ts";
import type { DevIdentity } from "./core/identity.ts";
import type { Store } from "./core/interfaces.ts";
import { KeyRing } from "./core/keys.ts";
import { PROTOCOL } from "./core/protocol.ts";
import { JsonlSecurityEvents, StdoutSecurityEvents } from "./core/security-events.ts";
import type { IdentityVerifier } from "./core/interfaces.ts";
import { parseAuthServerKeys } from "./oauth/keys.ts";
import { BindingState } from "./oauth/state.ts";
import type { BindingStore } from "./oauth/state.ts";
import { PostgresBindingStore } from "./storage/postgres-binding.ts";
import { InviteIdentityVerifier } from "./web/invites.ts";
import type { OrgPolicy } from "./core/types.ts";
import { FEDERATION_PATHS, brokerEntry } from "./federation/domain-authority.ts";
import { HardenedFetcher } from "./federation/fetcher.ts";
import { checkDevHostMap } from "./federation/net-guard.ts";
import { HttpsDomainResolver, systemTxtLookup } from "./federation/resolver.ts";
import { FederationServer } from "./federation/server.ts";
import { StaticResolver } from "./federation/static-resolver.ts";
import { HttpsFederationTransport } from "./federation/transport.ts";
import { LOCAL_ONLY_TRANSPORT } from "./dev-world.ts";
import { OidcRelyingParty, parseOidcConfig } from "./oauth/oidc.ts";
import { rateLimitsFromEnv } from "./limits-env.ts";
import { PolicyFiles } from "./policy-files.ts";
import { normalizePublicUrl, startBrokerServer, stopBroker } from "./server.ts";
import { FileStore } from "./storage/file.ts";
import { createPostgresStore } from "./storage/postgres.ts";
import { ConsoleOutboxNotifier } from "./web/notifier.ts";

export interface BrokerConfig {
  /** The broker's https origin: its id, its OAuth issuer and its public URL. */
  id: string;
  /** Domains whose people this broker is home for. */
  domains: string[];
  /** Paths (relative to the config file) of the private organization policies. */
  policies: string[];
  /**
   * Who can sign in. `dev`: fictional test identities, one secret each (evaluation). `invites`: people the operator
   * invites one by one (`npm run invite`), each with their own secret, then a passkey (a hosted broker: needs
   * DATABASE_URL and the public web view). `oidc`: the
   * organization's OpenID provider, generic or Microsoft Entra ID (src/oauth/oidc.ts parseOidcConfig; SELF-HOST.md).
   */
  identity: { kind: "dev"; identities: DevIdentity[] } | { kind: "invites" } | { kind: "oidc"; [setting: string]: unknown };
  /** Documentation only, never read: example `identity` blocks to copy (config.example.json). */
  identity_examples?: unknown;
  /** The person's web view: `public` serves it on the broker's own origin (ALP_WEB_PUBLIC=1 does too). */
  web?: { public?: boolean; rp_name?: string };
  /** Serve the federation inbox and JWKS, and discover other domains over HTTPS. Default false (the Local profile). */
  federation?: boolean;
  /** Bind people to these contact addresses for notifications (address -> email). */
  contacts?: Record<string, string>;
}

function intEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`${name} must be a port number`);
  return n;
}

async function loadKeys(store: Store, name: string, use: "federation" | "http", reseal: boolean): Promise<KeyRing> {
  const stored = await store.getKeyRing(name);
  if (stored) {
    // A ring stored before ALP_KEYRING_KEY was set is sealed now.
    if (reseal) await store.putKeyRing(name, stored);
    return KeyRing.fromJSON(stored);
  }
  const now = new Date();
  const keys = await KeyRing.generate(now, use);
  if (use === "federation") await keys.prepareNext(now);
  await store.putKeyRing(name, keys.toJSON());
  return keys;
}

async function main(): Promise<void> {
  const configPath = process.env["ALP_CONFIG"];
  if (!configPath) throw new Error("set ALP_CONFIG to the broker's JSON configuration (see config.example.json)");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as BrokerConfig;
  // The id is the broker's id in every envelope and receipt, its OAuth issuer and its public URL, and the protocol
  // requires https for it: a broker started with an http id would refuse every send (bad_envelope) and drop every
  // security event (the schemas refuse them). Loopback http is for the tests and `npm run dev` only.
  if (URL.parse(String(config.id))?.protocol !== "https:") {
    throw new Error("the configuration's `id` must be the broker's https origin, such as https://broker.example.org (it is the broker's id in envelopes, its OAuth issuer and its public URL). To evaluate on one machine, either keep an https id and call the loopback listener over the REST mirror with a personal access token (SELF-HOST.md, \"Evaluate on one machine\"), or put a TLS proxy in front of the broker at that origin.");
  }
  const id = normalizePublicUrl(config.id, "the configuration's `id`");
  const identityConfig = config.identity;
  if (identityConfig.kind !== "dev" && identityConfig.kind !== "invites" && identityConfig.kind !== "oidc") throw new Error('identity.kind must be "dev", "invites" or "oidc" (see SELF-HOST.md)');
  // Checked before anything starts, so a mistake in the identity block never leaves a half-configured broker.
  const oidcSettings = identityConfig.kind === "oidc" ? parseOidcConfig(identityConfig, config.domains) : undefined;
  const oidcSecret = process.env["ALP_OIDC_CLIENT_SECRET"] ?? "";
  if (oidcSettings && !oidcSecret) throw new Error("identity.kind \"oidc\" needs ALP_OIDC_CLIENT_SECRET (the broker's client secret at your identity provider)");
  // One secret per test identity, never one for everybody: on a broker more than one person uses, a shared secret
  // would let any of them sign in as any other.
  const identities: DevIdentity[] = identityConfig.kind === "dev" ? identityConfig.identities : [];
  // Read without echoing anything of the value: an error here never prints a secret.
  let given: Record<string, unknown> = {};
  if (identityConfig.kind === "dev" && process.env["ALP_DEV_LOGIN_SECRETS"]) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(process.env["ALP_DEV_LOGIN_SECRETS"]);
    } catch {
      parsed = undefined;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error('ALP_DEV_LOGIN_SECRETS must be a JSON object of one secret per test identity, such as {"ana": "<12 or more characters>", "lee": "<12 or more characters>"}');
    given = parsed as Record<string, unknown>;
  }
  const secrets: Record<string, string> = {};
  const generated: string[] = [];
  for (const who of identities) {
    const name = who.username.toLowerCase();
    const v = given[name] ?? given[who.username];
    if (v !== undefined && (typeof v !== "string" || [...v].length < 12)) throw new Error(`ALP_DEV_LOGIN_SECRETS: the secret for ${name} must be a string of at least 12 characters`);
    if (typeof v === "string") secrets[name] = v;
    else {
      secrets[name] = randomBytes(12).toString("base64url");
      generated.push(name);
    }
  }
  const devHosts = process.env["ALP_DEV_HOSTS"] ? checkDevHostMap(JSON.parse(process.env["ALP_DEV_HOSTS"]) as Record<string, string>) : undefined;
  const publicWeb = process.env["ALP_WEB_PUBLIC"] === "1" || config.web?.public === true;
  // The public web view signs people in by invite and passkey; signing in there through the organization's identity
  // provider isn't built yet.
  if (publicWeb && identityConfig.kind !== "invites") throw new Error("the web view on the public origin signs people in by invite and passkey: set identity.kind to \"invites\" (OIDC sign-in on the public web view isn't built yet)");
  // Invites are for a hosted broker. People sign in with them on the public web view, then register a passkey (on the
  // loopback view an invite would have no passkey after it), and `npm run invite` reaches a running broker only through
  // Postgres (the file store is read once, at start).
  if (identityConfig.kind === "invites" && (!publicWeb || !process.env["DATABASE_URL"])) throw new Error("identity.kind \"invites\" is for a hosted broker: set DATABASE_URL (npm run invite changes invites while the broker runs, which only Postgres shares) and ALP_WEB_PUBLIC=1 (people sign in on the public web view, then with a passkey)");
  const limits = rateLimitsFromEnv();
  const eventsTo = process.env["ALP_SECURITY_EVENTS"] || "file";
  if (eventsTo !== "file" && eventsTo !== "stdout") throw new Error("ALP_SECURITY_EVENTS must be file (security-events.jsonl in ALP_DATA_DIR, the default) or stdout");
  const hops = process.env["ALP_TRUSTED_PROXY_HOPS"] ? Number(process.env["ALP_TRUSTED_PROXY_HOPS"]) : 1;
  if (!Number.isInteger(hops) || hops < 1 || hops > 10) throw new Error("ALP_TRUSTED_PROXY_HOPS must be 1 to 10: the number of proxies in front that append to ALP_CLIENT_IP_HEADER");
  if ((process.env["HOST"] ?? "127.0.0.1") === "0.0.0.0" && !process.env["ALP_CLIENT_IP_HEADER"] && process.env["ALP_BEHIND_CLOUDFLARE"] !== "1") {
    console.warn("warning: HOST is 0.0.0.0 and neither ALP_CLIENT_IP_HEADER nor ALP_BEHIND_CLOUDFLARE is set. Behind a proxy, every request comes from the proxy's address, so the per-source limits (failed sign-ins, dynamic registrations, client metadata fetches, sign-in page requests) act as totals for everyone. Set ALP_CLIENT_IP_HEADER to the header your proxy sets (SELF-HOST.md, \"Reverse proxy and TLS\").");
  }
  const ttl = process.env["ALP_ACCESS_TOKEN_TTL"] ? Number(process.env["ALP_ACCESS_TOKEN_TTL"]) : undefined;
  if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 60 || ttl > 900)) throw new Error("ALP_ACCESS_TOKEN_TTL must be 60 to 900 seconds (spec 5.6.7)");
  // No outside DLP service is connected here (the Broker's `dlp` option stays unset, so the sample check runs), and a
  // policy that names one is refused rather than silently checked by the sample alone (spec 6.9).
  const policyFiles = PolicyFiles.load(config.policies.map((p) => resolve(dirname(configPath), p)));
  const policies: OrgPolicy[] = policyFiles.policies;
  const dataDir = resolve(process.env["ALP_DATA_DIR"] ?? join(process.cwd(), ".data", "broker"));
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbUrl = process.env["DATABASE_URL"];
  const kek = process.env["ALP_KEYRING_KEY"];
  if (kek && !dbUrl) throw new Error("ALP_KEYRING_KEY seals the signing keys in Postgres: set DATABASE_URL too (the file store keeps keys in a 0600 file)");
  if (dbUrl && !kek) console.warn("warning: DATABASE_URL is set without ALP_KEYRING_KEY: the broker's signing keys are stored unsealed in the database, so a copy of it (a backup, a dump) holds usable private keys. `npm run hosted-keys -- <new file>` makes a key; keep it outside the database.");
  for (const [i, p] of policies.entries()) {
    if (p.retention?.ledger_days !== undefined) console.warn(`warning: policy ${config.policies[i] ?? p.id} sets retention.ledger_days (${p.retention.ledger_days}): the broker records it but doesn't enforce it yet, and purges nothing.`);
  }
  const poolMax = process.env["ALP_DB_POOL_MAX"] ? Number(process.env["ALP_DB_POOL_MAX"]) : undefined;
  if (poolMax !== undefined && (!Number.isInteger(poolMax) || poolMax < 1 || poolMax > 50)) throw new Error("ALP_DB_POOL_MAX must be 1 to 50");
  const pg = dbUrl ? await createPostgresStore({ url: dbUrl, ...(process.env["ALP_DB_SCHEMA"] ? { schema: process.env["ALP_DB_SCHEMA"] } : {}), ...(kek ? { keyEncryptionKey: kek } : {}), ...(poolMax ? { max: poolMax } : {}) }) : undefined;
  const store: Store = pg ?? new FileStore(join(dataDir, "broker"));
  // The client binding's state goes where the broker's does: Postgres for a hosted broker, so any instance answers.
  const binding: BindingStore = pg ? new PostgresBindingStore(pg.sql) : BindingState.file(join(dataDir, "binding"));
  const authKeys = process.env["ALP_OAUTH_KEYS"] ? parseAuthServerKeys(process.env["ALP_OAUTH_KEYS"], "ALP_OAUTH_KEYS") : undefined;
  const keys = await loadKeys(store, "federation", "federation", pg?.sealsKeys === true);
  const httpKeys = await loadKeys(store, "http", "http", pg?.sealsKeys === true);
  const port = intEnv("PORT", 8080);
  const webPort = intEnv("WEB_PORT", 8081);
  const notifier = new ConsoleOutboxNotifier({ outboxPath: join(dataDir, "outbox.jsonl"), print: (t) => console.log(`\n${t}\n`) });
  const log = (line: string): void => console.log(`  ${new Date().toISOString()} ${line}`);
  // Discovery, the provider's key set and its token endpoint go through the hardened fetcher (spec 4.3).
  const oidc = oidcSettings ? new OidcRelyingParty({ settings: oidcSettings, clientSecret: oidcSecret, fetcher: new HardenedFetcher(devHosts ? { devHosts } : {}), log }) : undefined;
  const identity: IdentityVerifier = oidc ?? (identityConfig.kind === "invites" ? new InviteIdentityVerifier(binding, id) : new DevIdentityVerifier(identities, { secrets }));

  let resolver;
  let transport;
  let federation: FederationServer | undefined;
  if (config.federation) {
    const fetcher = new HardenedFetcher(devHosts ? { devHosts } : {});
    resolver = new HttpsDomainResolver({ fetcher, txt: systemTxtLookup });
    transport = new HttpsFederationTransport({ brokerId: id, fetcher, requestSigningKeys: httpKeys });
  }
  const broker = new Broker({
    id,
    store,
    keys,
    resolver: resolver ?? new StaticResolver(),
    transport: transport ?? LOCAL_ONLY_TRANSPORT,
    notifier,
    policies,
    domains: config.domains,
    securityEvents: eventsTo === "stdout" ? new StdoutSecurityEvents() : new JsonlSecurityEvents(join(dataDir, "security-events.jsonl")),
    webBaseUrl: publicWeb ? `${id}/web` : `http://127.0.0.1:${webPort}/web`,
    limits,
  });
  if (config.federation && resolver) {
    const signatures = process.env["ALP_REQUEST_SIGNATURES"] ?? "verify";
    if (signatures !== "verify" && signatures !== "require") throw new Error("ALP_REQUEST_SIGNATURES must be verify or require");
    federation = new FederationServer({ broker, inboxUrl: `${id}${FEDERATION_PATHS.inbox}`, jwksUrl: `${id}${FEDERATION_PATHS.jwks}`, extraKeys: () => httpKeys.jwks(), resolver, requestSignatures: signatures });
  }
  // Test identities are registered up front; with invites or OIDC, people are registered at their first sign-in.
  for (const who of identities) {
    const email = config.contacts?.[who.address] ?? who.address.replace(/^alp:/, "");
    await broker.registerPrincipal({ address: who.address, identity: { iss: DEV_ISSUER, sub: `dev-${who.username.toLowerCase()}` }, ...(who.display_name ? { display_name: who.display_name } : {}), contact: { email } });
  }
  const clientsFile = process.env["ALP_CLIENTS_FILE"];
  const redirectHosts = process.env["ALP_REDIRECT_HOSTS"] ? process.env["ALP_REDIRECT_HOSTS"].split(",").map((h) => h.trim().toLowerCase()).filter(Boolean) : undefined;
  const host = process.env["HOST"] ?? "127.0.0.1";
  const webHost = process.env["WEB_HOST"] ?? "127.0.0.1";
  const running = await startBrokerServer({
    broker,
    publicUrl: id,
    host,
    port,
    webPort,
    webHost,
    dataDir: join(dataDir, "binding"),
    bindingStore: binding,
    ...(authKeys ? { authKeys } : {}),
    ...(ttl !== undefined ? { accessTokenTtlSeconds: ttl } : {}),
    ...(pg ? { windows: pg } : {}),
    ...(publicWeb ? { publicWeb: { ...(config.web?.rp_name ? { rpName: config.web.rp_name } : {}) } } : {}),
    identity,
    idpMode: oidc ? "oidc" : "dev",
    ...(oidc ? { oidc } : {}),
    requireSecret: !oidc,
    // Each test identity has its own sign-in secret here, never one for everyone.
    ...(identityConfig.kind === "dev" ? { secretKind: "personal" as const } : {}),
    policies: () => policies,
    notifier,
    ...(redirectHosts ? { redirectHosts } : {}),
    requireApplicationType: process.env["ALP_DCR_REQUIRE_APPLICATION_TYPE"] !== "0",
    ...(clientsFile ? { staticClients: JSON.parse(readFileSync(clientsFile, "utf8")) as NonNullable<Parameters<typeof startBrokerServer>[0]["staticClients"]> } : {}),
    ...(federation ? { rawRoutes: [federation.handler()] } : {}),
    behindCloudflare: process.env["ALP_BEHIND_CLOUDFLARE"] === "1",
    ...(process.env["ALP_CLIENT_IP_HEADER"] ? { clientIpHeader: process.env["ALP_CLIENT_IP_HEADER"] } : {}),
    trustedProxyHops: hops,
    log,
  });

  const entry = brokerEntry({ id, keys: [keys, httpKeys], principals: "*", mcp: running.mcpUrl, rest: running.restUrl });
  console.log([
    "",
    `${PROTOCOL.name} reference broker (${dbUrl ? "Postgres" : "file"} store${pg?.sealsKeys ? ", signing keys sealed" : ""}). Sign-in: ${oidc ? `your organization's identity provider (OpenID Connect, ${oidc.settings.issuer})` : identityConfig.kind === "invites" ? "invites (npm run invite), then a passkey" : "the dev identity provider's test identities"}.`,
    `  Connector URL:  ${running.mcpUrl}`,
    `  REST mirror:    ${running.restUrl}`,
    `  Web view:       ${running.webUrl ?? ""} (${publicWeb ? "public origin: invites and passkeys" : "loopback only"})`,
    `  Listening:      ${host}:${port} (public listener: put TLS in front of it)${publicWeb ? "" : `, ${webHost}:${webPort} (web view)`}`,
    `  Health:         http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}/healthz and /readyz`,
    ...(oidc
      ? [
          "  Redirect URIs to register at the identity provider (web platform):",
          `    ${running.oidcRedirectUris?.connector ?? ""}`,
          ...(running.oidcRedirectUris?.web ? [`    ${running.oidcRedirectUris.web}`, `  and, for sign-out, the post-logout redirect URI ${running.webUrl ?? ""}`] : []),
          `  Agents' connections are ${oidc.settings.refreshCheck ? "re-checked at the identity provider at every refresh" : "NOT re-checked at the identity provider (refresh_check is off)"}.`,
        ]
      : identityConfig.kind === "dev"
        ? ["  Sign-in secrets, one per test identity (give each only to that person; set ALP_DEV_LOGIN_SECRETS to choose them):", ...identities.map((who) => `    ${who.username.padEnd(10)} ${generated.includes(who.username.toLowerCase()) ? secrets[who.username.toLowerCase()] : "(from ALP_DEV_LOGIN_SECRETS)"}`)]
        : ["  Invite people with `npm run invite -- create <name> <address>`; each gets their own secret, shown once."]),
    config.federation
      ? `\n  Federation is on. Publish this entry in https://<domain>/.well-known/${PROTOCOL.wellKnownFile} for each of ${config.domains.join(", ")} (adjust "principals"):\n${JSON.stringify(entry, null, 2).replace(/^/gm, "    ")}`
      : "\n  Federation is off (the Local profile): no domain document is needed.",
    "",
  ].join("\n"));

  const stop = async (): Promise<void> => {
    // The work after an answer (notices, pushes) finishes before the stores close.
    await stopBroker({ running, broker, stores: [binding, store] });
    log("stopped");
    process.exit(0);
  };
  process.on("SIGINT", () => void stop());
  process.on("SIGTERM", () => void stop());
  // Kill switches and other policy changes (spec 5.8): edit a policy file with a higher serial, then send this node
  // process SIGHUP (`kill -HUP <pid>`; npm doesn't pass the signal on). Each file is reloaded on its own
  // (src/policy-files.ts), and a new policy applies to the next request, reads and token refreshes included.
  process.on("SIGHUP", () => {
    void policyFiles.reload((next) => broker.setOrgPolicy({ kind: "admin", operator: "SIGHUP" }, next), (line) => console.log(`  ${line}`));
  });
  const pidFile = process.env["ALP_PID_FILE"];
  if (pidFile) writeFileSync(pidFile, `${process.pid}\n`, { mode: 0o644 });
}

main().catch((err: unknown) => {
  console.error(`broker failed to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
