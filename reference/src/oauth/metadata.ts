// SPDX-License-Identifier: FSL-1.1-ALv2
// Discovery documents (spec 5.6.1; MCP authorization; RFC 9728 and RFC 8414):
// - protected resource metadata for the MCP endpoint at /.well-known/oauth-protected-resource/mcp (RFC 9728's
//   path-inserted form, which clients try first) and at /.well-known/oauth-protected-resource (the root form some
//   clients use); for the REST mirror at /.well-known/oauth-protected-resource/rest. `resource` is the URL exactly as
//   a person enters it (https://<host>/mcp), and `authorization_servers` lists this broker's issuer only;
// - authorization server metadata at /.well-known/oauth-authorization-server (RFC 8414 for an issuer with no path),
//   the same document oidc-provider serves at /.well-known/openid-configuration, with
//   `client_id_metadata_document_supported`, `code_challenge_methods_supported: ["S256"]`,
//   `authorization_response_iss_parameter_supported` and `none` among the token endpoint methods.

import express from "express";
import type { Request, Response, Router } from "express";
import type Provider from "oidc-provider";
import { protectedResourceMetadata } from "./resource.ts";

export interface MetadataOptions {
  issuer: string;
  resources: { mcp: string; rest: string };
  provider: Provider;
  documentation?: string;
}

export function metadataRouter(opts: MetadataOptions): Router {
  const router = express.Router();
  const callback = opts.provider.callback();
  const send = (res: Response, doc: Record<string, unknown>): void => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.json(doc);
  };
  const mcpDoc = (req: Request): Record<string, unknown> =>
    protectedResourceMetadata(req.path.endsWith("/") ? `${opts.resources.mcp}/` : opts.resources.mcp, opts.issuer, opts.documentation);

  router.get("/.well-known/oauth-protected-resource", (_req, res) => send(res, protectedResourceMetadata(opts.resources.mcp, opts.issuer, opts.documentation)));
  router.get("/.well-known/oauth-protected-resource/mcp", (req, res) => send(res, mcpDoc(req)));
  router.get("/.well-known/oauth-protected-resource/rest", (_req, res) => send(res, protectedResourceMetadata(opts.resources.rest, opts.issuer, opts.documentation)));
  router.get("/.well-known/oauth-authorization-server", (req, res) => {
    // The same document as OpenID discovery: hand the request to oidc-provider under its discovery path.
    req.url = "/.well-known/openid-configuration";
    void callback(req, res);
  });
  return router;
}
