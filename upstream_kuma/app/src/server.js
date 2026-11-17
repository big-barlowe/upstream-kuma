import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './db.js';
import { Engine } from './engine.js';
import { checkers } from './checkers/index.js';
import { deliver } from './notifier.js';
import { createApi, HttpError, RawResponse } from './api.js';
import { IconCache } from './icons.js';
import { Auth } from './auth.js';
import { config, isAddon, log } from './config.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const INGRESS_IP = '172.30.32.2';
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
};

fs.mkdirSync(config.dataDir, { recursive: true });
// Before 0.16.0 the database was waterfall.db; take it over (with its WAL files) once.
const dbFile = path.join(config.dataDir, 'upstream-kuma.db');
const oldDb = path.join(config.dataDir, 'waterfall.db');
if (!fs.existsSync(dbFile) && fs.existsSync(oldDb)) {
  for (const ext of ['', '-wal', '-shm']) if (fs.existsSync(oldDb + ext)) fs.renameSync(oldDb + ext, dbFile + ext);
}
const store = new Store(dbFile);
const engine = new Engine({ store, checkers, notify: deliver });
const icons = new IconCache({ store, onChange: () => engine.touch() });
const auth = new Auth({ store, mode: config.auth, addon: isAddon, ingressIp: INGRESS_IP });
const api = createApi({ store, engine, icons, auth });

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new HttpError(413, 'Body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve(null);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new HttpError(400, 'Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

// Static files are public (they are the app, not data); the API decides who
// may see what. Opening the app signed out goes to the sign-in page.
function serveStatic(req, res, pathname) {
  if ((pathname === '/' || pathname === '/index.html') && !auth.identify(req)) {
    res.writeHead(302, { Location: 'login.html', 'Cache-Control': 'no-store' });
    return res.end();
  }
  const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (err, data) => {
    if (err) {
      // Unknown paths fall back to the app shell (hash routing does the rest).
      if (path.extname(rel)) return send(res, 404, { error: 'Not found' });
      return serveStatic(req, res, '/');
    }
    const headers = { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' };
    if (rel === 'login.html') headers['X-Frame-Options'] = 'SAMEORIGIN';
    res.writeHead(200, headers);
    res.end(data);
  });
}

// Under Home Assistant the UI is reached through ingress (which handles
// auth). If the direct port is mapped, only the push endpoint is reachable
// from outside unless the user opts in with allow_direct_access.
function allowed(req, pathname) {
  if (!isAddon || config.allowDirectAccess) return true;
  if (pathname.startsWith('/api/push/')) return true;
  return req.socket.remoteAddress?.replace(/^::ffff:/, '') === INGRESS_IP;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!allowed(req, url.pathname)) return send(res, 403, { error: 'Direct access is disabled; open Upstream Kuma from the Home Assistant sidebar.' });
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
  // Changes must come as JSON (see api() in util.js), except pushes from
  // other services.
  if (req.method !== 'GET' && !url.pathname.startsWith('/api/push/') && !/^application\/json\b/i.test(req.headers['content-type'] ?? '')) {
    return send(res, 415, { error: 'Send JSON (Content-Type: application/json)' });
  }
  try {
    // CSV imports can carry uploaded icons as data URLs
    const body = req.method === 'GET' ? null : await readBody(req, ['/api/csv/import', '/api/mibs'].includes(url.pathname) ? 32 * 1024 * 1024 : 1024 * 1024);
    const out = await api(req, url, body);
    if (out instanceof RawResponse) {
      res.writeHead(out.status, { 'Content-Type': out.type, ...out.headers });
      return res.end(out.body);
    }
    send(res, 200, out);
  } catch (err) {
    if (!(err instanceof HttpError)) log.error(`${req.method} ${url.pathname}:`, err);
    // `login` tells the page to go to the sign-in page
    send(res, err.status || 500, err.status === 401 ? { error: err.message, login: true } : { error: err.message });
  }
});

server.listen(config.port, () => {
  log.info(`Upstream Kuma listening on :${config.port} (data: ${config.dataDir}${isAddon ? ', Home Assistant add-on mode' : ''})`);
  if (auth.off) log.warn('AUTH=off: no sign-in, everyone who can reach the port is an admin');
  else if (auth.setupOpen()) log.info('No accounts yet: open the web UI to create the admin account');
  engine.start().catch((err) => log.error('Engine failed to start:', err));
  icons.sync(store.listMonitors());
  setInterval(() => icons.sync(store.listMonitors()), 6 * 3600 * 1000).unref();
});

function shutdown() {
  log.info('Shutting down');
  engine.stop();
  server.close();
  store.close();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
