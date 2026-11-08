// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run dev`: one Local-profile broker for example.org (and an outsider at outside.example), with the client
// binding: the MCP endpoint, the REST mirror, the OAuth authorization server and the connector sign-in page on the
// public port, and the person's web view on a loopback port. Fictional test identities only.
//
// Environment:
//   PUBLIC_URL           the public origin clients use, e.g. a tunnel's https://<name>.trycloudflare.com
//                        (default http://127.0.0.1:<PORT>, which only local clients can use)
//   PORT                 public listener on 127.0.0.1 (default 47110): point the tunnel here
//   WEB_PORT             the person's web view on 127.0.0.1 (default 47111): never tunnel this one
//   ALP_DATA_DIR          state, keys, outbox and security events (default ./.data/dev)
//   ALP_DEV_LOGIN_SECRET  the per-session secret test sign-ins need (default: generated and printed here)
//   ALP_REDIRECT_HOSTS    OAuth redirect hosts besides loopback (default claude.ai,chatgpt.com)
//   ALP_DCR_REQUIRE_APPLICATION_TYPE  set to 0 to accept dynamic registrations without application_type
//   ALP_CLIENTS_FILE      a JSON array of pre-registered OAuth clients (client_id, client_secret, redirect_uris...);
//                        an entry may add `alp_label`, `alp_attestation` and `alp_class`, which go into example.org's
//                        list of agents (spec 5.4; `org-client` needs a client that authenticates at the token endpoint)
//   ALP_ALLOWED_ORIGINS   extra browser Origins the MCP endpoint accepts, comma-separated (claude.ai and chatgpt.com
//                        are allowed already)
//   ALP_ACCESS_TOKEN_TTL  access token lifetime in seconds (default 600, at most 900)
//   ALP_DCR_ANY_PATH      set to 1 to let dynamically registered clients use any callback path on claude.ai and
//                        chatgpt.com (default: only the platforms' published callbacks, or loopback)
//   ALP_BEHIND_CLOUDFLARE 1 when the public port is reached only through a Cloudflare tunnel, so per-source limits use
//                        Cloudflare's CF-Connecting-IP (default: on when PUBLIC_URL is a *.trycloudflare.com origin)
//   ALP_DEFAULT_RATE_LIMIT, ALP_OWN_AGENT_RATE_LIMIT  message rate limits as count/seconds (src/limits-env.ts;
//                        defaults 120/3600 between two people, 600/3600 per pair of one person's own agents)
//   ALP_LOG               set to 0 to silence the request log

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { displayAddress } from "./core/address.ts";
import { JsonlSecurityEvents } from "./core/security-events.ts";
import { DEV_IDENTITIES, createDevBroker } from "./dev-world.ts";
import { rateLimitsFromEnv } from "./limits-env.ts";
import { normalizePublicUrl, startBrokerServer, stopBroker } from "./server.ts";
import type { Attestation, DelegateClass, OrgPolicy } from "./core/types.ts";
import { ConsoleOutboxNotifier } from "./web/notifier.ts";

function intEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`${name} must be a port number`);
  return n;
}

function portFree(port: number): Promise<boolean> {
  return new Promise((done) => {
    const s = createServer();
    s.once("error", () => done(false));
    s.listen(port, "127.0.0.1", () => s.close(() => done(true)));
  });
}

/** Four words and four digits (about 2^31 combinations); failed sign-ins are capped too. Easy to read aloud. */
function secretWords(): string {
  const words = ["amber", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor", "indigo", "juniper", "kelp", "lumen", "maple", "nectar", "orbit", "pebble", "quartz", "raven", "sable", "tundra", "umber", "vesper", "willow", "zephyr"];
  const bytes = randomBytes(6);
  const digits = String(((bytes[4] ?? 0) * 256 + (bytes[5] ?? 0)) % 10000).padStart(4, "0");
  return [...[0, 1, 2, 3].map((i) => words[(bytes[i] ?? 0) % words.length]), digits].join("-");
}

/**
 * Pre-registered clients from ALP_CLIENTS_FILE. `alp_label`, `alp_attestation` and `alp_class` (not OAuth metadata)
 * become an entry in example.org's list of agents, so the broker records what the operator says about the client.
 */
function withRecordedClients(entries: Record<string, unknown>[], policies: OrgPolicy[]): NonNullable<Parameters<typeof startBrokerServer>[0]["staticClients"]> {
  const policy = policies[0];
  const out: Record<string, unknown>[] = [];
  for (const raw of entries) {
    const { alp_label, alp_attestation, alp_class, ...metadata } = raw;
    if (policy?.clients && typeof metadata["client_id"] === "string" && (alp_attestation !== undefined || alp_class !== undefined)) {
      policy.clients.allowed = policy.clients.allowed.filter((c) => c.client_id !== metadata["client_id"]);
      policy.clients.allowed.push({
        client_id: metadata["client_id"],
        ...(typeof alp_label === "string" ? { label: alp_label } : {}),
        scopes: ["alp.availability/1", "alp.briefing/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"],
        attestation: (alp_attestation ?? "self") as Attestation,
        class: (alp_class ?? "consumer") as DelegateClass,
        no_training: false,
      });
    }
    out.push(metadata);
  }
  return out as NonNullable<Parameters<typeof startBrokerServer>[0]["staticClients"]>;
}

async function main(): Promise<void> {
  const port = intEnv("PORT", 47110);
  const webPort = intEnv("WEB_PORT", 47111);
  const publicUrl = normalizePublicUrl(process.env["PUBLIC_URL"] ?? `http://127.0.0.1:${port}`, "PUBLIC_URL");
  const dataDir = resolve(process.env["ALP_DATA_DIR"] ?? join(process.cwd(), ".data", "dev"));
  const secret = process.env["ALP_DEV_LOGIN_SECRET"] || secretWords();
  const quiet = process.env["ALP_LOG"] === "0";
  const say = (line: string): void => console.log(line);
  const log = (line: string): void => {
    if (!quiet) console.log(`  ${new Date().toISOString()} ${line}`);
  };

  for (const p of [port, webPort]) {
    if (!(await portFree(p))) {
      console.error(`Port ${p} on 127.0.0.1 is in use. Stop whatever holds it, or set PORT / WEB_PORT.`);
      process.exit(1);
    }
  }

  const webUrl = `http://127.0.0.1:${webPort}/web`;
  const notifier = new ConsoleOutboxNotifier({ outboxPath: join(dataDir, "outbox.jsonl"), print: (text) => say(`\n${text}\n`) });
  const { broker, policies, identity } = await createDevBroker({
    dataDir,
    webBaseUrl: webUrl,
    notifier,
    securityEvents: new JsonlSecurityEvents(join(dataDir, "security-events.jsonl")),
    secret,
    limits: rateLimitsFromEnv(),
  });
  const clientsFile = process.env["ALP_CLIENTS_FILE"];
  const staticClients = clientsFile ? withRecordedClients(JSON.parse(readFileSync(clientsFile, "utf8")) as Record<string, unknown>[], policies) : undefined;
  if (staticClients && policies[0]) {
    // The broker keeps its own copy of the policy: install the amended list as the next serial.
    policies[0].serial += 1;
    await broker.setOrgPolicy({ kind: "admin", operator: "npm run dev (ALP_CLIENTS_FILE)" }, policies[0]);
  }
  const redirectHosts = process.env["ALP_REDIRECT_HOSTS"] ? process.env["ALP_REDIRECT_HOSTS"].split(",").map((h) => h.trim().toLowerCase()).filter(Boolean) : undefined;
  const allowedOrigins = process.env["ALP_ALLOWED_ORIGINS"] ? process.env["ALP_ALLOWED_ORIGINS"].split(",").map((o) => o.trim()).filter(Boolean) : undefined;
  const ttl = process.env["ALP_ACCESS_TOKEN_TTL"] ? Number(process.env["ALP_ACCESS_TOKEN_TTL"]) : undefined;
  if (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 60 || ttl > 900)) throw new Error("ALP_ACCESS_TOKEN_TTL must be 60 to 900 seconds (spec 5.6.7)");
  const running = await startBrokerServer({
    broker,
    publicUrl,
    port,
    webPort,
    dataDir: join(dataDir, "binding"),
    identity,
    idpMode: "dev",
    requireSecret: true,
    policies: () => policies,
    notifier,
    ...(redirectHosts ? { redirectHosts } : {}),
    requireApplicationType: process.env["ALP_DCR_REQUIRE_APPLICATION_TYPE"] !== "0",
    ...(staticClients ? { staticClients } : {}),
    ...(allowedOrigins ? { allowedOrigins } : {}),
    ...(ttl !== undefined ? { accessTokenTtlSeconds: ttl } : {}),
    ...(process.env["ALP_DCR_ANY_PATH"] === "1" ? { dcrExactCallbacks: false } : {}),
    behindCloudflare: process.env["ALP_BEHIND_CLOUDFLARE"] !== undefined ? process.env["ALP_BEHIND_CLOUDFLARE"] === "1" : new URL(publicUrl).hostname.endsWith(".trycloudflare.com"),
    log,
  });

  say([
    "",
    "ALP reference broker (development). Fictional test identities only.",
    "",
    `  Connector URL (add this in Claude or ChatGPT):  ${running.mcpUrl}`,
    `  REST mirror:                                    ${running.restUrl}`,
    `  Public listener:  127.0.0.1:${port}   (point the tunnel here)`,
    `  Web view:         ${running.webUrl ?? ""}   (loopback only; approvals and the ledger)`,
    `  Broker id:        ${broker.id}`,
    `  Data:             ${dataDir}`,
    "",
    "  Test identities:",
    ...DEV_IDENTITIES.map((d) => `    ${d.username.padEnd(8)} ${displayAddress(d.address).padEnd(28)} ${d.display_name ?? ""}`),
    "",
    `  Session secret for test sign-ins (share only with the person at the keyboard):  ${secret}`,
    publicUrl.startsWith("http://") ? "\n  PUBLIC_URL is a loopback URL: hosted agents can't reach it. Set PUBLIC_URL to the tunnel's https origin." : "",
    "",
    "Ctrl-C stops the broker.",
    "",
  ].join("\n"));

  const stop = async (): Promise<void> => {
    say("\nStopping the broker...");
    // The work after an answer (notices, pushes) finishes before the process exits.
    await stopBroker({ running, broker });
    say("stopped");
    process.exit(0);
  };
  process.on("SIGINT", () => void stop());
  process.on("SIGTERM", () => void stop());
}

main().catch((err: unknown) => {
  console.error(`dev broker failed to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
