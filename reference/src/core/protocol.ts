// SPDX-License-Identifier: FSL-1.1-ALv2
// The protocol's name, in one place, so a rename is one find-and-replace over these strings. Keep them exactly as
// written: "Agent Liaison Protocol", "ALP", `alp`, `alp.`, `alp-`, `alp.json`, `_alp`, `alp_`.

export const PROTOCOL = {
  /** Display name. */
  name: "Agent Liaison Protocol",
  shortName: "ALP",
  /** Short id: the envelope version member, the address scheme (`alp:`), the scope prefix (`alp.`) and the typ prefix (`alp-`). */
  id: "alp",
  version: "0.1",
  /** Envelope member that carries the version. */
  versionField: "alp",
  addressScheme: "alp:",
  scopePrefix: "alp.",
  typPrefix: "alp-",
  /** File name under /.well-known/. */
  wellKnownFile: "alp.json",
  /** Optional host label: https://alp.<domain>/.well-known/alp.json */
  hostLabel: "alp",
  /** DNS TXT label: _alp.<domain> */
  txtLabel: "_alp",
  /** TXT record version tag: `v=ALP1; id=<serial>` */
  txtVersion: "ALP1",
  /** MCP and REST tool-name prefix: alp_send, alp_inbox... */
  toolPrefix: "alp_",
  /** OCSF profile name in security events. */
  ocsfProfile: "alp",
} as const;

export const ALP_VERSION = PROTOCOL.version;
