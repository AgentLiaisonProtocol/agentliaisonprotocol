// Imported first by every test file: any attempt to use the real network fails the test at once.
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";

const refuse = (what) => () => { throw new Error(`tests must not use the network (${what})`); };
globalThis.fetch = refuse("fetch");
net.Socket.prototype.connect = refuse("socket connect");
net.connect = refuse("net.connect");
net.createConnection = refuse("net.createConnection");
tls.connect = refuse("tls.connect");
http.request = refuse("http.request");
http.get = refuse("http.get");
https.request = refuse("https.request");
https.get = refuse("https.get");
dns.promises.resolveTxt = refuse("dns.promises.resolveTxt");
dns.promises.lookup = refuse("dns.promises.lookup");
dns.resolveTxt = refuse("dns.resolveTxt");
dns.lookup = refuse("dns.lookup");
