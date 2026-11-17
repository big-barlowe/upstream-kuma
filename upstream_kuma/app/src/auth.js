// Accounts: who a request is, password hashes, sessions, and what a viewer
// may see.
//
// - Under Home Assistant, ingress requests are already signed in to Home
//   Assistant, so they are admins. The direct port (allow_direct_access)
//   needs an account.
// - Standalone, every request needs an account; with none yet, the first
//   visit creates the admin (`setup`). AUTH=off turns this off (everyone is
//   an admin), for running behind a proxy that does its own sign-in.
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { scopeTest } from '../public/js/rules.js';

export { scopeTest };
import { HttpError } from './validate.js';

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
export const SESSION_COOKIE = 'uk_session';
export const SESSION_TTL = 30 * 86400000; // sliding: renewed while in use
const RENEW_AFTER = 3600000;
export const PASSWORD_MIN = 8;

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

// A hash to compare against when there is no such user, so a wrong username
// takes as long as a wrong password.
let dummy = null;

export async function verifyPassword(password, stored) {
  if (!stored) {
    dummy ??= await hashPassword(crypto.randomBytes(8).toString('hex'));
    await verifyPassword(password, dummy);
    return false;
  }
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(hash, 'base64');
  const got = await scrypt(String(password), Buffer.from(salt, 'base64'), want.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
  return crypto.timingSafeEqual(want, got);
}

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('base64url');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k && !(k in out)) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Whether the browser reached us over HTTPS (directly or through a proxy).
export const isHttps = (req) => Boolean(req.socket?.encrypted) || String(req.headers?.['x-forwarded-proto'] ?? '').split(',')[0].trim() === 'https';

export function cookie(name, value, { req, maxAge }) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (maxAge != null) parts.push(`Max-Age=${Math.floor(maxAge / 1000)}`);
  if (isHttps(req)) parts.push('Secure');
  return parts.join('; ');
}

export const clearCookie = (name, req) => cookie(name, '', { req, maxAge: 0 });

// What the client may know about an account.
export const publicUser = (u) => u && ({
  id: u.id,
  username: u.username,
  name: u.name,
  email: u.email,
  role: u.role,
  scope: u.scope,
  active: u.active,
  password: Boolean(u.passwordHash),
  sso: Boolean(u.oidcSub),
  ssoName: u.oidcSub ? u.oidcName || '' : '',
  createdAt: u.createdAt,
  lastLogin: u.lastLogin,
});

// What a viewer sees: the monitors its scope matches (`match`), those plus
// everything upstream of them (`visible`), and every tag a visible monitor
// carries (`tagIds`). Tags pick the monitors; the monitors then decide which
// tags the viewer can filter by (and whose icons it may load), so a Cabin
// viewer whose monitors are also tagged Virtual can filter by Virtual, and
// so on for the tags on the monitors upstream of them.
export function scopeView(user, { monitorIds, parentsOf, tagMap, tags }) {
  const test = scopeTest(user.scope, tags);
  const match = new Set();
  for (const id of monitorIds) if (test(tagMap.get(id) ?? [])) match.add(id);
  const visible = new Set(match);
  const queue = [...match];
  while (queue.length) {
    for (const p of parentsOf(queue.pop())) {
      if (visible.has(p)) continue;
      visible.add(p);
      queue.push(p);
    }
  }
  const tagIds = new Set();
  for (const id of visible) for (const x of tagMap.get(id) ?? []) tagIds.add(x);
  return { match, visible, tagIds };
}

// Failed sign-ins per client address: after LIMIT in WINDOW, wait.
const LIMIT = 10;
const WINDOW = 15 * 60000;

export class Throttle {
  constructor(now = Date.now) {
    this.now = now;
    this.fails = new Map();
  }

  check(key) {
    const f = this.fails.get(key);
    if (f && this.now() - f.first > WINDOW) this.fails.delete(key);
    else if (f && f.count >= LIMIT) {
      const wait = Math.ceil((f.first + WINDOW - this.now()) / 60000);
      throw new HttpError(429, `Too many failed sign-ins. Try again in ${wait} minute${wait === 1 ? '' : 's'}.`);
    }
  }

  fail(key) {
    const f = this.fails.get(key);
    if (f) f.count++;
    else this.fails.set(key, { first: this.now(), count: 1 });
    if (this.fails.size > 10000) this.fails.delete(this.fails.keys().next().value);
  }

  clear(key) {
    this.fails.delete(key);
  }
}

export const clientIp = (req) => String(req.socket?.remoteAddress ?? '').replace(/^::ffff:/, '');

// mode: 'accounts' (the default), or 'off' (everyone is an admin: tests,
// and AUTH=off). Under Home Assistant, `ingressIp` is the Supervisor's
// ingress proxy, whose requests are admins.
export class Auth {
  constructor({ store, mode = 'accounts', addon = false, ingressIp = null }) {
    this.store = store;
    this.mode = mode;
    this.addon = addon;
    this.ingressIp = ingressIp;
    this.throttle = new Throttle();
  }

  get off() {
    return this.mode === 'off';
  }

  // The first admin is created from the sign-in page. Under Home Assistant
  // that is done in Settings → Users instead, so that nobody on the network
  // can claim the add-on by reaching its port first.
  setupOpen() {
    return !this.off && !this.addon && this.store.countUsers() === 0;
  }

  // { user, via, tokenHash? } or null. `user` is a stored account, or for
  // ingress and AUTH=off a stand-in admin with id 0.
  identify(req) {
    if (this.off) return { user: { id: 0, username: 'admin', name: 'Admin', role: 'admin' }, via: 'open' };
    if (this.addon && clientIp(req) === this.ingressIp) {
      const hdr = req.headers ?? {};
      return {
        user: { id: 0, username: hdr['x-remote-user-name'] || 'homeassistant', name: hdr['x-remote-user-display-name'] || 'Home Assistant', role: 'admin' },
        via: 'ingress',
      };
    }
    const token = parseCookies(req.headers?.cookie)[SESSION_COOKIE];
    if (!token) return null;
    const tokenHash = sha256(token);
    const s = this.store.getSession(tokenHash);
    const now = Date.now();
    if (!s || s.expiresAt < now) return null;
    const user = this.store.getUser(s.userId);
    if (!user?.active) return null;
    if (now - s.seenAt > RENEW_AFTER) this.store.touchSession(tokenHash, now + SESSION_TTL);
    return { user, via: 'session', tokenHash };
  }

  // A new session for the user; returns the Set-Cookie header.
  startSession(user, req) {
    const token = randomToken();
    this.store.createSession(sha256(token), user.id, SESSION_TTL);
    this.store.updateUser(user.id, { lastLogin: Date.now() });
    return cookie(SESSION_COOKIE, token, { req, maxAge: SESSION_TTL });
  }

  async login(req, username, password) {
    const key = clientIp(req);
    this.throttle.check(key);
    const user = username ? this.store.findUser(String(username).trim()) : null;
    const ok = await verifyPassword(String(password ?? ''), user?.passwordHash ?? null);
    if (!ok || !user.active) {
      this.throttle.fail(key);
      throw new HttpError(401, ok ? 'This account is turned off' : 'Wrong username or password');
    }
    this.throttle.clear(key);
    return user;
  }
}
