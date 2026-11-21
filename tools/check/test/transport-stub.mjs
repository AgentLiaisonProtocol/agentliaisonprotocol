// A stand-in for node:https.request and dns.lookup, so that tests can run alp-check's own transport (the guarded
// lookup included) against the in-memory fake broker. It opens no socket and resolves no name: `addresses` maps a
// host name to the addresses the stand-in resolver returns. Licensed under Apache-2.0.
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";

export const PUBLIC_ADDRESS = "11.22.33.44";

export function stubTransport(fakeFetch, addresses = {}) {
  const lookups = [];
  const connections = [];
  const built = [];
  const resolve = (name, options, callback) => {
    lookups.push({ name, options });
    const list = addresses[name] ?? [PUBLIC_ADDRESS];
    if (!list.length) { process.nextTick(callback, Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" })); return; }
    process.nextTick(callback, null, list.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
  };
  const request = (options, onResponse) => {
    built.push(options);
    const req = new EventEmitter();
    let destroyed = false;
    req.destroy = (err) => { if (!destroyed) { destroyed = true; process.nextTick(() => req.emit("error", err ?? new Error("destroyed"))); } return req; };
    req.end = (body) => {
      // What net.connect does first: ask the lookup it was given for every address of the host.
      options.lookup(options.hostname, { all: true }, (err, list) => {
        if (destroyed) return;
        if (err) { req.emit("error", err); return; }
        connections.push({ host: options.hostname, addresses: list.map((a) => a.address) });
        const port = options.port === 443 && options.protocol === "https:" ? "" : `:${options.port}`;
        const url = `${options.protocol}//${options.hostname}${port}${options.path}`;
        Promise.resolve(fakeFetch(url, { method: options.method, headers: options.headers, body: body ?? null })).then(async (res) => {
          const buf = Buffer.from(await res.arrayBuffer());
          const msg = Readable.from(buf.length ? [buf] : []);
          msg.statusCode = res.status;
          msg.rawHeaders = [...res.headers].flat();
          onResponse(msg);
        }, (e) => req.emit("error", e));
      });
      return req;
    };
    return req;
  };
  return { resolve, request, lookups, connections, built };
}
