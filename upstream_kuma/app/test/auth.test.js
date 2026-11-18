import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Store } from '../src/db.js';
import { Engine } from '../src/engine.js';
import { createApi, RawResponse, redactAlert } from '../src/api.js';
import { Auth, hashPassword, verifyPassword, scopeView } from '../src/auth.js';
import { Oidc, verifyJwt } from '../src/oidc.js';

const icons = { describe: () => null, sync: () => {}, hasUpload: () => false, saveUpload: () => {} };

function setup({ addon = false, fetch } = {}) {
  const store = new Store(':memory:');
  const engine = new Engine({ store, checkers: { ping: () => ({ ok: true, ping: 1, msg: 'ok' }) }, notify: async () => [], schedule: () => null, cancel: () => {} });
  engine.reload();
  const auth = new Auth({ store, addon, ingressIp: '172.30.32.2' });
  const oidc = new Oidc({ store, fetch });
  const google = new Oidc({ store, fetch, id: 'google' });
  const handle = createApi({ store, engine, icons, auth, oidc, google });
  // A browser: keeps the cookies it is given.
  const browser = (ip = '10.0.0.9') => {
    const jar = new Map();
    const call = async (method, path, body) => {
      const req = { method, headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), host: 'uk.example' }, socket: { remoteAddress: ip } };
      const out = await handle(req, new URL(`http://uk.example${path}`), body);
      if (out instanceof RawResponse) {
        for (const c of [out.headers['Set-Cookie'] ?? []].flat()) {
          const [kv, ...attrs] = c.split('; ');
          const [k, v] = kv.split('=');
          if (attrs.includes('Max-Age=0')) jar.delete(k);
          else jar.set(k, v);
        }
        return out.status === 302 ? { location: out.headers.Location } : JSON.parse(out.body || 'null');
      }
      return out;
    };
    return { call, jar };
  };
  return { store, engine, auth, oidc, google, handle, browser };
}

const mon = (store, name, parents = [], tags = []) => {
  const id = store.createMonitor({ name, type: 'ping', config: { host: name }, interval: 60, retries: 0, retryInterval: 20, timeout: 5, resendInterval: 0, parentMode: 'all', active: true });
  for (const p of parents) store.addEdge(p, id);
  store.setMonitorTags(id, tags);
  return id;
};

async function withAdmin(t) {
  const admin = t.browser();
  await admin.call('POST', '/api/auth/setup', { username: 'alex', password: 'correct horse' });
  return admin;
}

test('passwords are salted scrypt hashes', async () => {
  const a = await hashPassword('hunter22');
  assert.match(a, /^scrypt\$16384\$8\$1\$/);
  assert.notEqual(a, await hashPassword('hunter22'));
  assert.equal(await verifyPassword('hunter22', a), true);
  assert.equal(await verifyPassword('hunter23', a), false);
  assert.equal(await verifyPassword('x', null), false);
});

test('a new install asks for the admin account, once', async () => {
  const t = setup();
  const b = t.browser();
  assert.deepEqual(await b.call('GET', '/api/auth/status'), { setup: true, signedIn: false, addon: false, sso: null, google: false, password: true });
  await assert.rejects(b.call('GET', '/api/state'), (e) => e.status === 401 && /Create the admin/.test(e.message));
  await assert.rejects(b.call('POST', '/api/auth/setup', { username: 'alex', password: 'short' }), /at least 8/);
  await b.call('POST', '/api/auth/setup', { username: 'alex', password: 'correct horse' });
  assert.equal((await b.call('GET', '/api/me')).role, 'admin');
  assert.equal(t.store.getUser(1).passwordHash.startsWith('scrypt$'), true);
  const other = t.browser();
  await assert.rejects(other.call('POST', '/api/auth/setup', { username: 'mallory', password: 'correct horse' }), (e) => e.status === 403);
  assert.equal((await other.call('GET', '/api/auth/status')).setup, false);
  await assert.rejects(other.call('GET', '/api/state'), (e) => e.status === 401 && /Sign in/.test(e.message));
  // the session cookie stores a hash server-side, not the token
  assert.notEqual(t.store.db.prepare('SELECT token FROM sessions').get().token, b.jar.get('uk_session'));

  await b.call('POST', '/api/auth/logout');
  await assert.rejects(b.call('GET', '/api/me'), (e) => e.status === 401);
});

test('sign-in: wrong passwords, turned-off accounts, the throttle', async () => {
  const t = setup();
  const admin = await withAdmin(t);
  await admin.call('POST', '/api/users', { username: 'kim', password: 'kim-password' });
  const b = t.browser('10.0.0.50');
  await assert.rejects(b.call('POST', '/api/auth/login', { username: 'kim', password: 'nope' }), /Wrong username or password/);
  await assert.rejects(b.call('POST', '/api/auth/login', { username: 'nobody', password: 'nope' }), /Wrong username or password/);
  await b.call('POST', '/api/auth/login', { username: 'KIM', password: 'kim-password' });
  const me = await b.call('GET', '/api/me');
  assert.deepEqual([me.username, me.role, me.via], ['kim', 'viewer', 'session']);

  // turning the account off ends its sessions
  await admin.call('PUT', `/api/users/${me.id}`, { active: false });
  await assert.rejects(b.call('GET', '/api/me'), (e) => e.status === 401);
  await assert.rejects(b.call('POST', '/api/auth/login', { username: 'kim', password: 'kim-password' }), /turned off/);

  const c = t.browser('10.0.0.51');
  for (let i = 0; i < 10; i++) await assert.rejects(c.call('POST', '/api/auth/login', { username: 'alex', password: 'wrong' }));
  await assert.rejects(c.call('POST', '/api/auth/login', { username: 'alex', password: 'correct horse' }), (e) => e.status === 429);
});

test('a viewer sees its scope and what is upstream of it, and changes nothing', async () => {
  const t = setup();
  const admin = await withAdmin(t);
  const a = t.store.createTag({ name: 'School A', color: '#60a5fa' });
  const b = t.store.createTag({ name: 'School B', color: '#e879f9' });
  const core = t.store.createTag({ name: 'Core', color: '#facc15' });
  const isp = t.store.createTag({ name: 'ISP', color: '#4ade80' });
  const wan = mon(t.store, 'WAN', [], [core, isp]);
  const router = mon(t.store, 'Router', [wan], [core]);
  const swA = mon(t.store, 'Switch A', [router], [a]);
  const apA = mon(t.store, 'AP A', [swA], [a, core]);
  const swB = mon(t.store, 'Switch B', [router], [b]);
  const lonely = mon(t.store, 'Elsewhere');
  t.engine.reload();
  const user = await admin.call('POST', '/api/users', { username: 'teacher', password: 'teacher-pass', scope: { tagIds: [a] } });
  assert.deepEqual(user.scope, { all: false, tagIds: [a], tagMatch: 'any', tagExpr: '' });

  const v = t.browser();
  await v.call('POST', '/api/auth/login', { username: 'teacher', password: 'teacher-pass' });
  const s = await v.call('GET', '/api/state');
  const names = s.monitors.map((m) => m.name).sort();
  assert.deepEqual(names, ['AP A', 'Router', 'Switch A', 'WAN']);
  const byName = new Map(s.monitors.map((m) => [m.name, m]));
  assert.deepEqual(byName.get('Router').children, [swA]); // not Switch B
  // tags: every one its monitors carry, upstream ones included (Core is
  // also on AP A, ISP only on the WAN), but not School B, which none does
  assert.deepEqual(s.tags.map((x) => x.name).sort(), ['Core', 'ISP', 'School A']);
  assert.deepEqual(byName.get('WAN').tags, [core, isp]);
  assert.deepEqual(byName.get('Switch A').tags, [a]);

  // reads of what it can see work; anything else is not found
  await v.call('GET', `/api/monitors/${wan}/heartbeats`);
  await v.call('GET', `/api/monitors/${apA}/uptime`);
  await assert.rejects(v.call('GET', `/api/monitors/${swB}/heartbeats`), (e) => e.status === 404);
  await assert.rejects(v.call('GET', `/api/monitors/${lonely}/events`), (e) => e.status === 404);
  // and it can't change anything or read settings
  for (const [method, path, body] of [
    ['GET', `/api/monitors/${swA}`], ['PUT', `/api/monitors/${swA}`, { name: 'x' }], ['DELETE', `/api/monitors/${swA}`],
    ['POST', `/api/monitors/${swA}/pause`], ['POST', `/api/monitors/${swA}/check`], ['POST', '/api/monitors', { name: 'x', type: 'ping' }],
    ['GET', '/api/tags'], ['POST', `/api/tags/${a}/apply`, { monitorIds: [swA] }], ['GET', '/api/rules'], ['GET', '/api/notifications'],
    ['GET', '/api/problems'], ['GET', '/api/settings'], ['GET', '/api/users'], ['GET', '/api/sso'], ['GET', '/api/csv/export'],
    ['POST', '/api/mibs', { files: [] }], ['PUT', `/api/users/${user.id}`, { role: 'admin' }],
  ]) await assert.rejects(v.call(method, path, body), (e) => e.status === 403, `${method} ${path}`);

  // events only for what it sees
  t.store.addHeartbeat({ monitorId: swB, status: 0, time: 1, msg: 'x', important: true });
  assert.ok((await v.call('GET', '/api/events')).every((e) => [wan, router, swA, apA].includes(e.monitorId)));

  // a scope change shows on the next poll
  const before = t.engine.version;
  await admin.call('PUT', `/api/users/${user.id}`, { scope: { tagExpr: '"School A" or "School B"' } });
  assert.ok(t.engine.version > before);
  assert.equal((await v.call('GET', '/api/state')).monitors.length, 5);
  // renaming a tag keeps the expression working
  await admin.call('PUT', `/api/tags/${b}`, { name: 'School Bee', color: '#e879f9' });
  assert.match(t.store.getUser(user.id).scope.tagExpr, /School Bee/);
  assert.equal((await v.call('GET', '/api/state')).monitors.length, 5);
});

test('scopes never widen by accident', () => {
  const tags = [{ id: 1, name: 'A' }, { id: 2, name: 'B' }];
  const tagMap = new Map([[10, [1]], [11, [2]], [12, []]]);
  const parents = new Map([[10, [12]], [11, [12]], [12, []]]);
  const view = (scope) => [...scopeView({ scope }, { monitorIds: [10, 11, 12], parentsOf: (id) => parents.get(id), tagMap, tags }).visible].sort();
  assert.deepEqual(view({}), []);
  assert.deepEqual(view({ tagIds: [] }), []);
  assert.deepEqual(view({ tagIds: [9] }), []); // its tag was deleted
  assert.deepEqual(view({ tagExpr: 'A' }), [10, 12]);
  assert.deepEqual(view({ tagExpr: 'A and (' }), []); // broken
  assert.deepEqual(view({ tagExpr: 'Nope' }), []);
  assert.deepEqual(view({ tagIds: [1, 2], tagMatch: 'all' }), []);
  assert.deepEqual(view({ tagIds: [1, 2] }), [10, 11, 12]);
  assert.deepEqual(view({ all: true }), [10, 11, 12]);
});

test('alerts a viewer sees list only the monitors it can see', () => {
  const a = {
    id: 1, monitorId: 1, kind: 'down', title: 'Down: Router',
    message: 'Router is down\nReason: timeout\n\nOther affected monitors (3):\n- Switch A\n-- AP A\n- Switch B',
    affected: [{ id: 2, name: 'Switch A', depth: 1 }, { id: 3, name: 'AP A', depth: 2 }, { id: 4, name: 'Switch B', depth: 1 }],
    delivered: [{ name: 'Phone', ok: true }],
  };
  const r = redactAlert(a, new Set([1, 2, 3]));
  assert.equal(r.message, 'Router is down\nReason: timeout\n\nOther affected monitors (2):\n- Switch A\n-- AP A');
  assert.deepEqual(r.affected.map((x) => x.id), [2, 3]);
  assert.deepEqual(r.delivered, [{ ok: true, name: 'Sent' }]);
  assert.equal(redactAlert(a, new Set([1])).message, 'Router is down\nReason: timeout');
});

test('accounts: the last admin stays, nobody deletes themselves', async () => {
  const t = setup();
  const admin = await withAdmin(t);
  const me = await admin.call('GET', '/api/me');
  await assert.rejects(admin.call('PUT', `/api/users/${me.id}`, { role: 'viewer' }), /at least one admin/);
  await assert.rejects(admin.call('DELETE', `/api/users/${me.id}`), /your own account/);
  await assert.rejects(admin.call('POST', '/api/users', { username: 'kim' }), /password/);
  await assert.rejects(admin.call('POST', '/api/users', { username: 'Alex', password: 'whatever1' }), /already a user/);
  const kim = await admin.call('POST', '/api/users', { username: 'kim', password: 'whatever1', role: 'admin' });
  assert.equal(kim.password, true);
  assert.equal('passwordHash' in kim, false);
  await admin.call('PUT', `/api/users/${me.id}`, { role: 'viewer' });

  // changing your own password keeps this session and ends the others
  const k1 = t.browser();
  const k2 = t.browser();
  await k1.call('POST', '/api/auth/login', { username: 'kim', password: 'whatever1' });
  await k2.call('POST', '/api/auth/login', { username: 'kim', password: 'whatever1' });
  await assert.rejects(k1.call('PUT', '/api/me/password', { current: 'nope', password: 'whatever2' }), /current password/);
  await k1.call('PUT', '/api/me/password', { current: 'whatever1', password: 'whatever2' });
  await k1.call('GET', '/api/me');
  await assert.rejects(k2.call('GET', '/api/me'), (e) => e.status === 401);
});

test('under Home Assistant, ingress is an admin and the direct port needs an account', async () => {
  const t = setup({ addon: true });
  const ingress = t.browser('172.30.32.2');
  assert.deepEqual(await ingress.call('GET', '/api/me'), { id: 0, username: 'homeassistant', name: 'Home Assistant', email: '', role: 'admin', via: 'ingress', password: false, sso: false, ssoName: '', google: false, googleName: '' });
  const direct = t.browser('192.168.1.20');
  // no setup from the network: accounts are made in Settings, through ingress
  assert.equal((await direct.call('GET', '/api/auth/status')).setup, false);
  await assert.rejects(direct.call('POST', '/api/auth/setup', { username: 'x', password: 'xxxxxxxx' }), (e) => e.status === 403);
  await assert.rejects(direct.call('GET', '/api/state'), (e) => e.status === 401);
  // with no admin account at all (ingress always is one)
  const u = await ingress.call('POST', '/api/users', { username: 'kim', password: 'whatever1', role: 'admin' });
  await ingress.call('PUT', `/api/users/${u.id}`, { role: 'viewer' });
  // pushes need no account
  await assert.rejects(direct.call('GET', '/api/push/nope'), (e) => e.status === 404);
});

// ---- single sign-on against a fake provider ---------------------------------

const ISSUER = 'https://idp.example';
const DEFAULT_ISSUER = ISSUER;

// `issuer` is the provider's; `iss` what its ID tokens say (Google's say
// either of two).
function fakeIdp({ issuer: ISSUER = DEFAULT_ISSUER, iss = ISSUER } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' };
  const idp = { codes: new Map(), claims: {}, tamper: false, requests: [] };
  const sign = (claims) => {
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const data = `${enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${enc(claims)}`;
    let sig = crypto.sign('sha256', Buffer.from(data), privateKey).toString('base64url');
    if (idp.tamper) sig = sig.slice(0, -4) + 'AAAA';
    return `${data}.${sig}`;
  };
  idp.fetch = async (url, init = {}) => {
    const u = new URL(url);
    idp.requests.push({ url: u, init });
    const reply = (body, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
    if (u.pathname === '/.well-known/openid-configuration') {
      return reply({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks`, userinfo_endpoint: `${ISSUER}/userinfo` });
    }
    if (u.pathname === '/jwks') return reply({ keys: [jwk] });
    if (u.pathname === '/token') {
      const form = new URLSearchParams(init.body);
      const c = idp.codes.get(form.get('code'));
      if (!c) return reply({ error: 'invalid_grant' }, 400);
      const challenge = crypto.createHash('sha256').update(form.get('code_verifier')).digest('base64url');
      if (challenge !== c.challenge) return reply({ error: 'invalid_grant', error_description: 'PKCE' }, 400);
      const now = Math.floor(Date.now() / 1000);
      return reply({ access_token: 'at', id_token: sign({ iss, aud: idp.aud ?? 'uk', exp: now + 300, iat: now, nonce: c.nonce, ...idp.claims }) });
    }
    if (u.pathname === '/userinfo') return reply({ sub: idp.claims.sub, groups: idp.claims.userinfoGroups ?? [] });
    return reply({}, 404);
  };
  // The provider signs the user in and sends the browser back.
  idp.authorize = (location) => {
    const u = new URL(location);
    const code = crypto.randomBytes(8).toString('hex');
    idp.codes.set(code, { nonce: u.searchParams.get('nonce'), challenge: u.searchParams.get('code_challenge') });
    return { code, state: u.searchParams.get('state'), redirect: u.searchParams.get('redirect_uri') };
  };
  return idp;
}

async function ssoSignIn(t, idp, browser, next = '') {
  const start = await browser.call('GET', `/api/auth/oidc/start?next=${encodeURIComponent(next)}`);
  const { code, state, redirect } = idp.authorize(start.location);
  assert.equal(redirect, 'http://uk.example/api/auth/oidc/callback');
  return browser.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}`);
}

test('SSO: settings, linking by email, creating accounts, the admin group', async () => {
  const idp = fakeIdp();
  const t = setup({ fetch: idp.fetch });
  const admin = await withAdmin(t);
  await assert.rejects(admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER }), /client ID/);
  await assert.rejects(admin.call('PUT', '/api/sso', { enabled: true, issuer: `${ISSUER}/wrong`, clientId: 'uk' }), /answered 404/);
  const saved = await admin.call('PUT', '/api/sso', { enabled: true, issuer: `${ISSUER}/`, clientId: 'uk', clientSecret: 's3cret', label: 'Authentik' });
  assert.equal(saved.clientSecret, undefined);
  assert.equal(saved.hasSecret, true);
  assert.equal(saved.redirectUri, 'http://uk.example/api/auth/oidc/callback');
  // a blank secret keeps the saved one
  await admin.call('PUT', '/api/sso', { label: 'Authentik', clientSecret: '' });
  assert.equal(t.oidc.config().clientSecret, 's3cret');
  assert.deepEqual((await t.browser().call('GET', '/api/auth/status')).sso, { label: 'Authentik' });

  // The authorize URL carries PKCE, state and nonce; the token call the secret.
  const b = t.browser();
  const start = await b.call('GET', '/api/auth/oidc/start?next=%23%2Fmonitor%2F3');
  const q = new URL(start.location).searchParams;
  assert.deepEqual([q.get('response_type'), q.get('client_id'), q.get('code_challenge_method'), q.get('scope')], ['code', 'uk', 'S256', 'openid profile email']);
  assert.equal(q.get('prompt'), null); // the provider may sign in whoever it already knows
  assert.ok(b.jar.get('uk_oidc'));

  // no account with that email yet
  idp.claims = { sub: 'u-1', email: 'kim@example.com', email_verified: true, name: 'Kim', preferred_username: 'kim' };
  let res = await ssoSignIn(t, idp, b);
  assert.match(decodeURIComponent(res.location), /^\.\.\/\.\.\/\.\.\/login\.html\?error=No Upstream Kuma account goes with that sign-in/);
  assert.doesNotMatch(decodeURIComponent(res.location), /kim/); // nothing about who, or which accounts exist

  // an account with that email is linked on first sign-in
  const kim = await admin.call('POST', '/api/users', { username: 'kim', email: 'Kim@Example.com', scope: { all: true } });
  assert.equal(kim.password, false);
  res = await ssoSignIn(t, idp, b, '#/monitor/3');
  assert.equal(res.location, '../../../#/monitor/3');
  const me = await b.call('GET', '/api/me');
  assert.deepEqual([me.username, me.role, me.sso], ['kim', 'viewer', true]);
  assert.equal(t.store.getUser(kim.id).oidcSub, `${ISSUER} u-1`);
  // the Users page and the account say which identity is linked
  assert.equal(me.ssoName, 'kim@example.com');
  assert.equal((await admin.call('GET', '/api/users')).find((u) => u.id === kim.id).ssoName, 'kim@example.com');
  assert.equal(idp.requests.find((r) => r.url.pathname === '/token').init.headers.Authorization, `Basic ${Buffer.from('uk:s3cret').toString('base64')}`);

  // a stranger gets an empty viewer when accounts are created on sign-in
  await admin.call('PUT', '/api/sso', { autoCreate: true, adminGroup: 'uk-admins' });
  idp.claims = { sub: 'u-2', email: 'sam@example.com', preferred_username: 'kim' };
  const s = t.browser();
  await ssoSignIn(t, idp, s);
  const sam = await s.call('GET', '/api/me');
  assert.deepEqual([sam.username, sam.role], ['kim-2', 'viewer']);
  assert.equal((await s.call('GET', '/api/state')).monitors.length, 0);
  // the admin group (here from userinfo) makes an admin, and leaving it undoes that
  idp.claims = { sub: 'u-2', email: 'sam@example.com', userinfoGroups: ['uk-admins'] };
  await ssoSignIn(t, idp, s);
  assert.equal((await s.call('GET', '/api/me')).role, 'admin');
  idp.claims = { sub: 'u-2', email: 'sam@example.com', userinfoGroups: [] };
  await ssoSignIn(t, idp, s);
  assert.equal((await s.call('GET', '/api/me')).role, 'viewer');

  // With password sign-in off, only admins may still use one.
  await admin.call('PUT', '/api/sso', { passwordLogin: false });
  await admin.call('POST', '/api/users', { username: 'pat', password: 'whatever1' });
  await assert.rejects(t.browser().call('POST', '/api/auth/login', { username: 'pat', password: 'whatever1' }), /Sign in with Authentik/);
  await t.browser().call('POST', '/api/auth/login', { username: 'alex', password: 'correct horse' });

  // asking for the provider's account picker every time
  await admin.call('PUT', '/api/sso', { selectAccount: true });
  assert.equal(new URL((await t.browser().call('GET', '/api/auth/oidc/start')).location).searchParams.get('prompt'), 'select_account');
});

test('SSO: the Users page shows which identity an account is linked to', async () => {
  const idp = fakeIdp();
  const t = setup({ fetch: idp.fetch });
  const admin = await withAdmin(t);
  await admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER, clientId: 'uk' });
  const ab = await admin.call('POST', '/api/users', { username: 'abarlowe', email: 'abarlowe@domain.org', role: 'admin' });
  const ax = await admin.call('POST', '/api/users', { username: 'adminalex', email: 'adminalex@domain.org', role: 'admin' });
  const signIn = async (claims) => {
    idp.claims = claims;
    const b = t.browser();
    await ssoSignIn(t, idp, b);
    return b.call('GET', '/api/me');
  };
  // Entra: no email_verified, the UPN as preferred_username
  assert.equal((await signIn({ sub: 'e-1', email: 'abarlowe@domain.org', preferred_username: 'abarlowe@domain.org' })).username, 'abarlowe');
  assert.equal((await signIn({ sub: 'e-2', email: 'adminalex@domain.org', preferred_username: 'adminalex@domain.org' })).username, 'adminalex');
  // without an email the username names it
  assert.equal((await signIn({ sub: 'e-2', preferred_username: 'adminalex@domain.org' })).ssoName, 'adminalex@domain.org');
  // A link wins over the email. If an identity is linked to the wrong
  // account, the page shows it under that account, and Unlink fixes it.
  t.store.updateUser(ab.id, { oidcSub: `${ISSUER} e-3` });
  t.store.updateUser(ax.id, { oidcSub: null });
  assert.equal((await signIn({ sub: 'e-3', email: 'adminalex@domain.org' })).username, 'abarlowe');
  const users = await admin.call('GET', '/api/users');
  assert.equal(users.find((u) => u.id === ab.id).ssoName, 'adminalex@domain.org');
  await admin.call('PUT', `/api/users/${ab.id}`, { unlinkSso: true });
  assert.deepEqual([t.store.getUser(ab.id).oidcSub, t.store.getUser(ab.id).oidcName], [null, '']);
  assert.equal((await signIn({ sub: 'e-3', email: 'adminalex@domain.org' })).username, 'adminalex');
});

test('SSO: replays, other browsers and bad signatures are refused', async () => {
  const idp = fakeIdp();
  const t = setup({ fetch: idp.fetch });
  const admin = await withAdmin(t);
  await admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER, clientId: 'uk', autoCreate: true });
  idp.claims = { sub: 'u-9', email: 'x@example.com' };

  // the callback in a browser that didn't start the sign-in
  const a = t.browser();
  const start = await a.call('GET', '/api/auth/oidc/start');
  const { code, state } = idp.authorize(start.location);
  const other = t.browser();
  let res = await other.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}`);
  assert.match(decodeURIComponent(res.location), /different browser/);
  // and the state is used up
  res = await a.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}`);
  assert.match(decodeURIComponent(res.location), /expired or was started elsewhere/);

  idp.tamper = true;
  res = await ssoSignIn(t, idp, a);
  assert.match(decodeURIComponent(res.location), /signature is not valid/);
  idp.tamper = false;

  // the provider's own error
  const s2 = await a.call('GET', '/api/auth/oidc/start');
  const st = new URL(s2.location).searchParams.get('state');
  res = await a.call('GET', `/api/auth/oidc/callback?state=${st}&error=access_denied&error_description=${encodeURIComponent('User said no')}`);
  assert.match(decodeURIComponent(res.location), /User said no/);
  assert.equal(t.store.listUsers().length, 1);

  // an open redirect through `next` is not possible
  const s3 = await a.call('GET', `/api/auth/oidc/start?next=${encodeURIComponent('https://evil.example')}`);
  const x = idp.authorize(s3.location);
  res = await a.call('GET', `/api/auth/oidc/callback?code=${x.code}&state=${x.state}`);
  assert.equal(res.location, '../../../');
});

test('JWT checks: HS256 with the client secret, wrong keys', () => {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const data = `${enc({ alg: 'HS256' })}.${enc({ sub: '1' })}`;
  const sig = crypto.createHmac('sha256', 'shh').update(data).digest('base64url');
  assert.equal(verifyJwt(`${data}.${sig}`, { keys: [], secret: 'shh' }).claims.sub, '1');
  assert.throws(() => verifyJwt(`${data}.${sig}`, { keys: [], secret: 'nope' }), /signature/);
  assert.throws(() => verifyJwt(`${enc({ alg: 'none' })}.${enc({})}.`, { keys: [] }), /Unsupported/);
  assert.throws(() => verifyJwt(`${enc({ alg: 'RS256', kid: 'zz' })}.${enc({})}.AA`, { keys: [{ kid: 'k1', kty: 'RSA' }] }), /keys matches/);
});

test('SSO from a home-screen app: the sign-in window hands over, confirming when it has other cookies', async () => {
  const idp = fakeIdp();
  const t = setup({ fetch: idp.fetch });
  const admin = await withAdmin(t);
  await admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER, clientId: 'uk' });
  await admin.call('POST', '/api/users', { username: 'kim', name: 'Kim', email: 'kim@example.com', role: 'admin' });
  idp.claims = { sub: 'u-1', email: 'kim@example.com', email_verified: true };
  const signInWindow = async (win, id, extra = '') => {
    const start = await win.call('GET', `/api/auth/oidc/start?next=${encodeURIComponent('#/monitor/3')}&handoff=${id}`);
    const { code, state } = idp.authorize(start.location);
    return win.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}${extra}`);
  };

  // iOS: the window has cookies of its own, so it asks first
  const app = t.browser();
  const { id, code } = await app.call('POST', '/api/auth/oidc/handoff', {});
  assert.match(code, /^\d{4}$/);
  assert.deepEqual(await app.call('POST', '/api/auth/oidc/handoff/claim', {}), { waiting: true, confirming: false });
  const win = t.browser();
  assert.equal((await signInWindow(win, id)).location, '../../../login.html?handoff=confirm');
  await assert.rejects(win.call('GET', '/api/me'), /401|sign in/i); // nobody signed in there
  assert.deepEqual(await app.call('POST', '/api/auth/oidc/handoff/claim', {}), { waiting: true, confirming: true });
  assert.deepEqual(await win.call('GET', '/api/auth/oidc/handoff/confirm'), { code, name: 'Kim' });
  // only that window can answer, and only the app can claim
  await assert.rejects(t.browser().call('POST', '/api/auth/oidc/handoff/confirm', {}), /expired/);
  assert.deepEqual(await t.browser().call('POST', '/api/auth/oidc/handoff/claim', {}), { expired: true });
  await win.call('POST', '/api/auth/oidc/handoff/confirm', {});
  assert.deepEqual(await app.call('POST', '/api/auth/oidc/handoff/claim', {}), { signedIn: true });
  assert.equal((await app.call('GET', '/api/me')).username, 'kim');
  assert.equal(app.jar.has('uk_handoff'), false);
  await assert.rejects(win.call('POST', '/api/auth/oidc/handoff/confirm', {}), /expired/); // used up

  // a window sharing the app's cookies (Android, desktop) just signs in
  const app2 = t.browser();
  const h2 = await app2.call('POST', '/api/auth/oidc/handoff', {});
  assert.equal((await signInWindow(app2, h2.id)).location, '../../../login.html?signed-in=1#/monitor/3');
  assert.deepEqual(await app2.call('POST', '/api/auth/oidc/handoff/claim', {}), { signedIn: true });

  // cancelled in the window, or refused by the provider: the app hears why
  const app3 = t.browser();
  const h3 = await app3.call('POST', '/api/auth/oidc/handoff', {});
  const win3 = t.browser();
  await signInWindow(win3, h3.id);
  await win3.call('POST', '/api/auth/oidc/handoff/confirm', { cancel: true });
  assert.deepEqual(await app3.call('POST', '/api/auth/oidc/handoff/claim', {}), { error: 'The sign-in was cancelled' });
  assert.deepEqual(await app3.call('POST', '/api/auth/oidc/handoff/claim', {}), { expired: true });
  await assert.rejects(app3.call('GET', '/api/me'), /401|sign in/i);

  const app4 = t.browser();
  const h4 = await app4.call('POST', '/api/auth/oidc/handoff', {});
  const win4 = t.browser();
  const s4 = await win4.call('GET', `/api/auth/oidc/start?handoff=${h4.id}`);
  const st = new URL(s4.location).searchParams.get('state');
  await win4.call('GET', `/api/auth/oidc/callback?state=${st}&error=access_denied&error_description=${encodeURIComponent('User said no')}`);
  assert.deepEqual(await app4.call('POST', '/api/auth/oidc/handoff/claim', {}), { error: 'User said no' });

  // no account for whoever signed in
  const app5 = t.browser();
  const h5 = await app5.call('POST', '/api/auth/oidc/handoff', {});
  idp.claims = { sub: 'u-5', email: 'nobody@example.com', email_verified: true };
  await signInWindow(t.browser(), h5.id);
  assert.match((await app5.call('POST', '/api/auth/oidc/handoff/claim', {})).error, /No Upstream Kuma account goes with/);
});

const GOOGLE = 'https://accounts.google.com';
const GOOGLE_ID = '123-abc.apps.googleusercontent.com';

// Both providers at once: the generic one and Google, told apart by host.
function twoIdps() {
  const idp = fakeIdp();
  const g = fakeIdp({ issuer: GOOGLE, iss: 'accounts.google.com' });
  g.aud = GOOGLE_ID;
  const fetch = (url, init) => (new URL(url).host === 'accounts.google.com' ? g.fetch : idp.fetch)(url, init);
  return { idp, g, fetch };
}

async function googleSignIn(g, browser, claims) {
  g.claims = claims;
  const start = await browser.call('GET', '/api/auth/oidc/start?provider=google');
  const { code, state } = g.authorize(start.location);
  return browser.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}`);
}

test('Google: settings, and which addresses find an account by themselves', async () => {
  const { idp, g, fetch } = twoIdps();
  const t = setup({ fetch });
  const admin = await withAdmin(t);
  await assert.rejects(admin.call('PUT', '/api/google', { clientId: 'uk' }), /apps\.googleusercontent\.com/);
  await assert.rejects(admin.call('PUT', '/api/google', { enabled: true, clientId: GOOGLE_ID }), /client secret/);
  const saved = await admin.call('PUT', '/api/google', { enabled: true, clientId: GOOGLE_ID, clientSecret: 'gsecret' });
  assert.deepEqual([saved.enabled, saved.hasSecret, saved.clientSecret, saved.redirectUri], [true, true, undefined, 'http://uk.example/api/auth/oidc/callback']);
  assert.deepEqual(await t.browser().call('GET', '/api/auth/status'), { setup: false, signedIn: false, addon: false, sso: null, google: true, password: true });

  // the authorize URL: Google's, its account picker by default
  const start = new URL((await t.browser().call('GET', '/api/auth/oidc/start?provider=google')).location);
  assert.equal(start.origin, GOOGLE);
  assert.deepEqual([start.searchParams.get('client_id'), start.searchParams.get('prompt'), start.searchParams.get('scope')], [GOOGLE_ID, 'select_account', 'openid email profile']);

  const kim = await admin.call('POST', '/api/users', { username: 'kim', email: 'Kim@gmail.com', scope: { all: true } });
  const pat = await admin.call('POST', '/api/users', { username: 'pat@gmail.com', scope: { all: true } });
  const lee = await admin.call('POST', '/api/users', { username: 'lee', email: 'lee@corp.example' });
  const sam = await admin.call('POST', '/api/users', { username: 'sam', email: 'sam@outlook.com', password: 'sam-password' });
  const off = await admin.call('POST', '/api/users', { username: 'off', email: 'off@gmail.com', active: false });
  const signIn = async (claims) => {
    const b = t.browser();
    const res = await googleSignIn(g, b, claims);
    return { b, location: decodeURIComponent(res.location), me: await b.call('GET', '/api/me').catch(() => null) };
  };
  const refused = (r, address) => {
    assert.equal(r.me, null);
    assert.match(r.location, /^\.\.\/\.\.\/\.\.\/login\.html\?error=No Upstream Kuma account goes with that sign-in/);
    if (address) assert.ok(!r.location.includes(address), r.location);
  };

  // Gmail, by the account's email or by its username
  let r = await signIn({ sub: 'g-kim', email: 'kim@gmail.com', email_verified: true, name: 'Kim' });
  assert.deepEqual([r.me.username, r.me.google, r.me.googleName, r.me.sso], ['kim', true, 'kim@gmail.com', false]);
  assert.equal(t.store.getUser(kim.id).googleSub, `${GOOGLE} g-kim`);
  assert.equal(t.store.getUser(kim.id).oidcSub, null);
  assert.equal((await signIn({ sub: 'g-pat', email: 'pat@gmail.com', email_verified: true })).me.id, pat.id);
  // and from then on by the link, whatever the address says
  assert.equal((await signIn({ sub: 'g-kim', email: 'kim.new@gmail.com', email_verified: true })).me.id, kim.id);
  // a Workspace domain: Google vouches for it (`hd`)
  assert.equal((await signIn({ sub: 'g-lee', email: 'lee@corp.example', email_verified: true, hd: 'corp.example' })).me.id, lee.id);

  // Not these: an address Google doesn't own, an hd that isn't the address's,
  // an unverified Gmail, a turned-off account. The page says the same thing
  // for each, without the address.
  refused(await signIn({ sub: 'g-sam', email: 'sam@outlook.com', email_verified: true }), 'sam@outlook.com');
  refused(await signIn({ sub: 'g-sam2', email: 'sam@outlook.com', email_verified: true, hd: 'corp.example' }), 'sam@outlook.com');
  refused(await signIn({ sub: 'g-x', email: 'kim2@gmail.com', email_verified: false }));
  refused(await signIn({ sub: 'g-off', email: 'off@gmail.com', email_verified: true }), 'off@gmail.com');
  refused(await signIn({ sub: 'g-new', email: 'stranger@gmail.com', email_verified: true }), 'stranger');
  assert.equal(t.store.getUser(sam.id).googleSub, null);
  assert.equal(t.store.getUser(off.id).googleSub, null);
  assert.equal(t.store.listUsers().length, 6); // nobody was made

  // A token for another client is refused.
  g.aud = 'someone-else.apps.googleusercontent.com';
  assert.match((await signIn({ sub: 'g-kim', email: 'kim@gmail.com', email_verified: true })).location, /different client/);
  g.aud = GOOGLE_ID;

  // With passwords for admins only, viewers are told what to use.
  await admin.call('PUT', '/api/sso/passwords', { everyone: false });
  await assert.rejects(t.browser().call('POST', '/api/auth/login', { username: 'sam', password: 'sam-password' }), /Sign in with Google instead/);
  await admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER, clientId: 'uk' });
  await assert.rejects(t.browser().call('POST', '/api/auth/login', { username: 'sam', password: 'sam-password' }), /Sign in with Single sign-on or Google instead/);
  await admin.call('PUT', '/api/sso/passwords', { everyone: true });
  assert.equal(t.oidc.config().passwordLogin, true);
  void idp;
});

test('Google: an account links its own Google account, which stays apart from the SSO link', async () => {
  const { idp, g, fetch } = twoIdps();
  const t = setup({ fetch });
  const admin = await withAdmin(t);
  await admin.call('PUT', '/api/google', { enabled: true, clientId: GOOGLE_ID, clientSecret: 'gsecret' });
  await admin.call('PUT', '/api/sso', { enabled: true, issuer: ISSUER, clientId: 'uk' });
  const sam = await admin.call('POST', '/api/users', { username: 'sam', email: 'sam@outlook.com', password: 'sam-password' });
  const kim = await admin.call('POST', '/api/users', { username: 'kim', email: 'kim@example.com' });
  const link = async (b, claims, provider = g) => {
    provider.claims = claims;
    const start = await b.call('GET', `/api/auth/oidc/start?provider=${provider === g ? 'google' : 'oidc'}&link=1`);
    if (!start.location.startsWith('http')) return decodeURIComponent(start.location);
    const { code, state } = provider.authorize(start.location);
    return decodeURIComponent((await b.call('GET', `/api/auth/oidc/callback?code=${code}&state=${state}`)).location);
  };

  // signed out, there's nothing to link to
  assert.match(await link(t.browser(), { sub: 'g-sam', email: 'sam@outlook.com', email_verified: true }), /^\.\.\/\.\.\/\.\.\/#\/settings\/account\?link-error=Sign in first/);

  const b = t.browser();
  await b.call('POST', '/api/auth/login', { username: 'sam', password: 'sam-password' });
  assert.equal(await link(b, { sub: 'g-sam', email: 'sam@outlook.com', email_verified: true }), '../../../#/settings/account?linked=google');
  assert.deepEqual([(await b.call('GET', '/api/me')).google, (await b.call('GET', '/api/me')).googleName], [true, 'sam@outlook.com']);
  // now the Google sign-in finds sam
  const b2 = t.browser();
  await googleSignIn(g, b2, { sub: 'g-sam', email: 'sam@outlook.com', email_verified: true });
  assert.equal((await b2.call('GET', '/api/me')).username, 'sam');
  // the generic provider's link is a separate one
  assert.equal(await link(b, { sub: 'o-sam', email: 'sam@outlook.com' }, idp), '../../../#/settings/account?linked=oidc');
  const u = t.store.getUser(sam.id);
  assert.deepEqual([u.googleSub, u.oidcSub], [`${GOOGLE} g-sam`, `${ISSUER} o-sam`]);

  // A Google account linked to someone else stays theirs.
  const k = t.browser();
  idp.claims = { sub: 'o-kim', email: 'kim@example.com' };
  await ssoSignIn(t, idp, k);
  assert.equal((await k.call('GET', '/api/me')).username, 'kim');
  assert.match(await link(k, { sub: 'g-sam', email: 'sam@outlook.com', email_verified: true }), /link-error=That Google account is linked to another Upstream Kuma account/);
  assert.equal(t.store.getUser(kim.id).googleSub, null);

  // The callback must come back to the session that started it.
  const start = await k.call('GET', '/api/auth/oidc/start?provider=google&link=1');
  g.claims = { sub: 'g-kim', email: 'kim@outlook.com', email_verified: true };
  const x = g.authorize(start.location);
  k.jar.delete('uk_session');
  assert.match(decodeURIComponent((await k.call('GET', `/api/auth/oidc/callback?code=${x.code}&state=${x.state}`)).location), /link-error=Sign in again/);
  assert.equal(t.store.getUser(kim.id).googleSub, null);

  // Unlinking your own: fine with another way in, refused if it's the only one.
  await b.call('POST', '/api/me/unlink', { provider: 'google' });
  assert.equal(t.store.getUser(sam.id).googleSub, null);
  t.store.updateUser(kim.id, { oidcSub: null, googleSub: `${GOOGLE} g-kim` });
  const k2 = t.browser();
  await googleSignIn(g, k2, { sub: 'g-kim', email: 'kim@outlook.com', email_verified: true });
  await assert.rejects(k2.call('POST', '/api/me/unlink', { provider: 'google' }), /stays linked/);
  // an admin can, from the Users page
  await admin.call('PUT', `/api/users/${kim.id}`, { unlinkGoogle: true });
  assert.deepEqual([t.store.getUser(kim.id).googleSub, t.store.getUser(kim.id).googleName], [null, '']);
  assert.equal((await admin.call('GET', '/api/users')).find((x2) => x2.id === kim.id).google, false);
});
