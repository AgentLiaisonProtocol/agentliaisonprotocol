// SPDX-License-Identifier: FSL-1.1-ALv2
// Web view sessions (spec 12.5.2): a random session id in a cookie, server-side state in the binding store (keyed by
// the id's SHA-256, so a copy of the store holds no usable session), a 15-minute idle timeout, and a per-session CSRF
// token that every POST must carry. GET never changes anything.
//
// - On a public (HTTPS) origin: the cookie is `__Host-alp_web; Path=/; Secure; HttpOnly; SameSite=Strict` with no
//   Max-Age (it ends with the browser), the server ends a session after 15 idle minutes or 12 hours in all, and a second
//   cookie (`__Host-alp_device`, a year) recognizes the browser for the notice on sign-in from a new device.
// - On the loopback web view (the default): `alp_web; Path=/; HttpOnly; SameSite=Strict; Max-Age=900` (`__Host-` and
//   Secure can't apply on plain HTTP), and the 15-minute idle timeout.

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, Response } from "express";
import type { Address, SealMethod } from "../core/types.ts";
import { sha256b64u } from "../oauth/state.ts";
import type { BindingStore, WebSessionRecord } from "../oauth/state.ts";

export interface WebSession {
  /** The cookie's value; never stored. */
  id: string;
  idHash: string;
  principal: Address;
  principal_id: string;
  username: string;
  csrf: string;
  stage: WebSessionRecord["stage"];
  /** When the person last proved who they are (sign-in or a step-up), epoch ms. */
  authAt: number;
  method: SealMethod;
  createdAt: number;
  lastSeen: number;
  deviceHash?: string;
  newDevice?: boolean;
  /** OIDC sign-ins: the identity the session belongs to (iss + sub; Entra: the tenant's issuer + oid). */
  identity?: { iss: string; sub: string };
}

export const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
/** A session on a public origin ends after this long whatever happens. */
export const MAX_SESSION_MS = 12 * 3600 * 1000;
/** last_seen is written at most this often (the idle timeout is exact to within it). */
const TOUCH_MS = 30 * 1000;

function toRecord(s: WebSession): WebSessionRecord {
  return {
    id_hash: s.idHash,
    principal: s.principal,
    principal_id: s.principal_id,
    username: s.username,
    csrf: s.csrf,
    stage: s.stage,
    auth_at: s.authAt,
    method: s.method,
    created_at: s.createdAt,
    last_seen: s.lastSeen,
    ...(s.deviceHash ? { device_hash: s.deviceHash } : {}),
    ...(s.newDevice ? { new_device: true } : {}),
    ...(s.identity ? { identity: { iss: s.identity.iss, sub: s.identity.sub } } : {}),
  };
}

function fromRecord(id: string, r: WebSessionRecord): WebSession {
  return {
    id,
    idHash: r.id_hash,
    principal: r.principal as Address,
    principal_id: r.principal_id,
    username: r.username,
    csrf: r.csrf,
    stage: r.stage,
    authAt: r.auth_at,
    method: r.method,
    createdAt: r.created_at,
    lastSeen: r.last_seen,
    ...(r.device_hash ? { deviceHash: r.device_hash } : {}),
    ...(r.new_device ? { newDevice: true } : {}),
    ...(r.identity ? { identity: { iss: r.identity.iss, sub: r.identity.sub } } : {}),
  };
}

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return undefined;
}

export class WebSessions {
  readonly cookieName: string;
  readonly deviceCookieName: string;
  private readonly secure: boolean;
  private readonly store: BindingStore;

  constructor(opts: { secure: boolean; store: BindingStore }) {
    this.secure = opts.secure;
    this.store = opts.store;
    this.cookieName = opts.secure ? "__Host-alp_web" : "alp_web";
    this.deviceCookieName = "__Host-alp_device";
  }

  private setCookie(res: Response, value: string, maxAge?: number): void {
    const attrs = `Path=/; HttpOnly; SameSite=Strict${this.secure ? "; Secure" : ""}${maxAge !== undefined ? `; Max-Age=${maxAge}` : ""}`;
    res.append("Set-Cookie", `${this.cookieName}=${value}; ${attrs}`);
  }

  async current(req: Request, now: number): Promise<WebSession | undefined> {
    const id = readCookie(req, this.cookieName);
    if (!id || id.length > 128) return undefined;
    const idHash = sha256b64u(id);
    const r = await this.store.getWebSession(idHash);
    if (!r) return undefined;
    if (now - r.last_seen > IDLE_TIMEOUT_MS || (this.secure && now - r.created_at > MAX_SESSION_MS)) {
      await this.store.deleteWebSession(idHash);
      return undefined;
    }
    const s = fromRecord(id, r);
    if (now - s.lastSeen > TOUCH_MS) {
      s.lastSeen = now;
      await this.store.putWebSession(toRecord(s));
    }
    return s;
  }

  /**
   * The live session whose id has this SHA-256 (base64url): an OIDC step-up's callback, which the SameSite=Strict
   * cookie doesn't reach. `id` is empty in what it returns (the cookie didn't come with the request).
   */
  async findByHash(idHash: string, now: number): Promise<WebSession | undefined> {
    if (!idHash || idHash.length > 128) return undefined;
    const r = await this.store.getWebSession(idHash);
    if (!r) return undefined;
    if (now - r.last_seen > IDLE_TIMEOUT_MS || (this.secure && now - r.created_at > MAX_SESSION_MS)) {
      await this.store.deleteWebSession(idHash);
      return undefined;
    }
    const s = fromRecord("", r);
    s.lastSeen = now;
    await this.store.putWebSession(toRecord(s));
    return s;
  }

  async start(res: Response, who: Omit<WebSession, "id" | "idHash" | "csrf" | "lastSeen" | "createdAt">, now: number): Promise<WebSession> {
    const id = randomBytes(32).toString("base64url");
    const s: WebSession = { ...who, id, idHash: sha256b64u(id), csrf: randomBytes(24).toString("base64url"), lastSeen: now, createdAt: now };
    await this.store.putWebSession(toRecord(s));
    this.setCookie(res, s.id, this.secure ? undefined : IDLE_TIMEOUT_MS / 1000);
    return s;
  }

  /** Write the session's changes (stage, step-up time). */
  async save(s: WebSession): Promise<void> {
    await this.store.putWebSession(toRecord(s));
  }

  /** Replace the session's id and CSRF token (when its sign-in completes), keeping what it holds. */
  async rotate(res: Response, s: WebSession, now: number, changes: Partial<Pick<WebSession, "stage" | "authAt" | "method" | "deviceHash" | "newDevice">>): Promise<WebSession> {
    await this.store.deleteWebSession(s.idHash);
    const { id: _id, idHash: _h, csrf: _c, lastSeen: _l, createdAt: _cr, ...rest } = s;
    return this.start(res, { ...rest, ...changes }, now);
  }

  async end(req: Request, res: Response): Promise<void> {
    const id = readCookie(req, this.cookieName);
    if (id && id.length <= 128) await this.store.deleteWebSession(sha256b64u(id));
    this.setCookie(res, "", 0);
  }

  /** The browser's device id (public origin only): read it, or set a new one for a year. */
  device(req: Request, res: Response): string {
    const have = readCookie(req, this.deviceCookieName);
    if (have && /^[A-Za-z0-9_-]{43}$/.test(have)) return have;
    const id = randomBytes(32).toString("base64url");
    res.append("Set-Cookie", `${this.deviceCookieName}=${id}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${365 * 86400}`);
    return id;
  }

  csrfOk(s: WebSession, given: unknown): boolean {
    if (typeof given !== "string") return false;
    const a = Buffer.from(s.csrf);
    const b = Buffer.from(given);
    return a.length === b.length && timingSafeEqual(a, b);
  }
}
