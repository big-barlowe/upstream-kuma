import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Store } from '../src/db.js';
import { Engine } from '../src/engine.js';
import { createApi, RawResponse } from '../src/api.js';
import { Auth } from '../src/auth.js';
import { deliver } from '../src/notifier.js';
import { encrypt, pushPayload, pushServiceOk, pushTopic, vapidHeader, vapidKeys, WebPush } from '../src/webpush.js';

const hkdf = (salt, ikm, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));

// A browser's side of a subscription: its keys, and decryption as RFC 8291
// says the browser does it.
function fakeBrowserKeys() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const auth = crypto.randomBytes(16);
  const keys = { p256dh: ecdh.getPublicKey().toString('base64url'), auth: auth.toString('base64url') };
  const decrypt = (body) => {
    const salt = body.subarray(0, 16);
    assert.equal(body.readUInt32BE(16), 4096);
    const asPublic = body.subarray(21, 21 + body[20]);
    const ct = body.subarray(21 + body[20]);
    const ikm = hkdf(auth, ecdh.computeSecret(asPublic), Buffer.concat([Buffer.from('WebPush: info\0'), ecdh.getPublicKey(), asPublic]), 32);
    const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
    const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);
    const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
    d.setAuthTag(ct.subarray(-16));
    const plain = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
    assert.equal(plain.at(-1), 2); // the last record's delimiter
    return JSON.parse(plain.subarray(0, -1).toString('utf8'));
  };
  return { keys, decrypt };
}

test('payloads are encrypted so the browser can read them, and signed with VAPID', () => {
  const b = fakeBrowserKeys();
  const body = encrypt(Buffer.from(JSON.stringify({ hello: 'phone' })), b.keys);
  assert.deepEqual(b.decrypt(body), { hello: 'phone' });
  // a fresh key and salt every time
  assert.notDeepEqual(encrypt(Buffer.from('x'), b.keys).subarray(0, 16), encrypt(Buffer.from('x'), b.keys).subarray(0, 16));

  const keys = vapidKeys();
  const header = vapidHeader('https://web.push.apple.com/QGx/abc', keys, 'https://uk.example.com', Date.UTC(2026, 0, 1));
  const [, t, k] = /^vapid t=([^,]+), k=(.+)$/.exec(header);
  assert.equal(k, keys.publicKey);
  const [h, c, sig] = t.split('.');
  const claims = JSON.parse(Buffer.from(c, 'base64url'));
  assert.deepEqual([JSON.parse(Buffer.from(h, 'base64url')).alg, claims.aud, claims.sub, claims.exp], ['ES256', 'https://web.push.apple.com', 'https://uk.example.com', Date.UTC(2026, 0, 1) / 1000 + 12 * 3600]);
  const pub = Buffer.from(keys.publicKey, 'base64url');
  const key = crypto.createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') } });
  assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${c}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url')));
});

test('only real push services, over https', () => {
  for (const ok of ['https://web.push.apple.com/abc', 'https://fcm.googleapis.com/fcm/send/x', 'https://updates.push.services.mozilla.com/wpush/v2/x', 'https://wns2-par02p.notify.windows.com/w/?token=x']) assert.ok(pushServiceOk(ok), ok);
  for (const bad of ['http://web.push.apple.com/abc', 'https://192.168.1.1/x', 'https://push.apple.com.evil.example/x', 'https://homeassistant.local:8123/api', 'nonsense']) assert.ok(!pushServiceOk(bad), bad);
});

test('what a phone shows: one line, the downstream count it may see, and where a tap goes', () => {
  const a = {
    kind: 'down',
    title: 'Alert: Switch is unreachable',
    message: 'long text',
    monitor: { id: 7, name: 'Switch' },
    affected: [{ id: 8, name: 'AP 1', depth: 1 }, { id: 9, name: 'AP 2', depth: 1 }],
    facts: [{ key: 'reason', label: 'Reason', value: 'No reply' }],
    time: 1,
  };
  assert.deepEqual(pushPayload(a), { title: a.title, body: 'No reply · 2 downstream affected', url: '#/?focus=7&info=7', tag: 'monitor-7', kind: 'down', level: 'urgent', time: 1 });
  assert.equal(pushPayload(a, new Set([7, 8])).body, 'No reply · 1 downstream affected');
  assert.equal(pushPayload({ ...a, kind: 'up', facts: [], affected: [] }).body, 'long text');
  assert.ok(Buffer.byteLength(JSON.stringify(pushPayload({ ...a, title: 'x'.repeat(5000), facts: [{ key: 'reason', value: 'y'.repeat(5000) }] }))) < 3000);
});

test('the Topic is always 32 base64url characters, and a service that refuses it gets none', async () => {
  // Apple answered `monitor-5` with BadWebPushTopic
  for (const tag of ['monitor-5', 'monitor-12345', 'test-1763500000000', 'x']) {
    assert.match(pushTopic(tag), /^[A-Za-z0-9_-]{32}$/);
  }
  assert.equal(pushTopic('monitor-5'), pushTopic('monitor-5'));
  assert.notEqual(pushTopic('monitor-5'), pushTopic('monitor-6'));

  const settings = new Map();
  const store = { getSetting: (k) => settings.get(k), setSetting: (k, v) => settings.set(k, v) };
  const sent = [];
  const fetch = async (url, init) => {
    sent.push(init.headers.Topic);
    return init.headers.Topic
      ? { ok: false, status: 400, text: async () => '{"reason":"BadWebPushTopic"}' }
      : { ok: true, status: 201, text: async () => '' };
  };
  const wp = new WebPush({ store, viewFor: () => null, fetch });
  const { keys } = fakeBrowserKeys();
  await wp.sendTo({ endpoint: 'https://web.push.apple.com/x', origin: 'https://uk.example.com', ...keys }, pushPayload({ kind: 'down', title: 'Down', monitor: { id: 5 } }));
  assert.deepEqual(sent, [pushTopic('monitor-5'), undefined]);
});

// ---- through the API ------------------------------------------------------------

function setup() {
  const store = new Store(':memory:');
  const engine = new Engine({ store, checkers: {}, notify: async () => [], schedule: () => null, cancel: () => {} });
  engine.reload();
  const auth = new Auth({ store });
  // the push services: every request, and what each endpoint answers
  const service = { requests: [], status: new Map() };
  const pushFetch = async (url, init) => {
    service.requests.push({ url, init });
    const status = service.status.get(url) ?? 201;
    return { ok: status < 300, status, text: async () => (status < 300 ? '' : 'nope') };
  };
  const handle = createApi({ store, engine, icons: { describe: () => null, sync: () => {} }, auth, pushFetch });
  const browser = () => {
    const jar = new Map();
    const call = async (method, path, body) => {
      const req = { method, headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), host: 'uk.example' }, socket: { remoteAddress: '10.0.0.5' } };
      const out = await handle(req, new URL(`http://uk.example${path}`), body);
      if (out instanceof RawResponse) {
        for (const c of [out.headers['Set-Cookie'] ?? []].flat()) {
          const [kv] = c.split('; ');
          const [k, v] = kv.split('=');
          jar.set(k, v);
        }
        return JSON.parse(out.body || 'null');
      }
      return out;
    };
    return { call };
  };
  return { store, engine, service, browser };
}

const subscription = (endpoint, keys) => ({ endpoint, keys });

test('devices sign up to push channels, and each hears what its account may see', async () => {
  const t = setup();
  const admin = t.browser();
  await admin.call('POST', '/api/auth/setup', { username: 'alex', password: 'correct horse' });
  const cams = t.store.createTag({ name: 'Cameras', color: '#0ea5e9' });
  const core = t.store.createMonitor({ name: 'Core', type: 'ping', config: { host: 'a' }, interval: 60, retries: 0, retryInterval: 20, timeout: 5, resendInterval: 0, parentMode: 'all', active: true });
  const cam = t.store.createMonitor({ name: 'Cam', type: 'ping', config: { host: 'b' }, interval: 60, retries: 0, retryInterval: 20, timeout: 5, resendInterval: 0, parentMode: 'all', active: true });
  const nas = t.store.createMonitor({ name: 'NAS', type: 'ping', config: { host: 'c' }, interval: 60, retries: 0, retryInterval: 20, timeout: 5, resendInterval: 0, parentMode: 'all', active: true });
  t.store.addEdge(core, cam);
  t.store.addEdge(core, nas);
  t.store.setMonitorTags(cam, [cams]);
  t.engine.reload();
  await admin.call('POST', '/api/users', { username: 'vic', password: 'viewer pass', scope: { tagIds: [cams] } });
  const viewer = t.browser();
  await viewer.call('POST', '/api/auth/login', { username: 'vic', password: 'viewer pass' });

  const ch = await admin.call('POST', '/api/notifications', { name: 'Phones', type: 'webpush', config: {} });
  const other = await admin.call('POST', '/api/notifications', { name: 'Email', type: 'webhook', config: { url: 'https://hooks.example/x' } });
  const info = await viewer.call('GET', '/api/webpush');
  assert.deepEqual(info.channels, [{ id: ch.id, name: 'Phones', active: true }]);
  assert.equal(Buffer.from(info.publicKey, 'base64url').length, 65);
  assert.equal((await admin.call('GET', '/api/webpush')).publicKey, info.publicKey); // one key pair

  const pa = fakeBrowserKeys();
  const pv = fakeBrowserKeys();
  // anything but a push service is refused: the server would post to it
  await assert.rejects(viewer.call('POST', '/api/webpush/devices', { subscription: subscription('https://192.168.1.10/hook', pv.keys) }), /push service/);
  const devA = await admin.call('POST', '/api/webpush/devices', { subscription: subscription('https://web.push.apple.com/alex', pa.keys), name: 'Alex iPhone', channelIds: [ch.id, other.id, 999], origin: 'https://uk.example.com' });
  assert.deepEqual([devA.name, devA.channelIds, devA.service], ['Alex iPhone', [ch.id], 'Apple']); // only push channels
  const devV = await viewer.call('POST', '/api/webpush/devices', { subscription: subscription('https://web.push.apple.com/vic', pv.keys), name: 'Vic iPhone', channelIds: [ch.id], origin: 'https://uk.example.com' });
  assert.equal((await admin.call('GET', '/api/notifications')).find((n) => n.id === ch.id).devices, 2);
  // nobody touches someone else's device
  await assert.rejects(viewer.call('DELETE', `/api/webpush/devices/${devA.id}`), /not found/);
  assert.deepEqual((await viewer.call('GET', '/api/webpush')).devices.map((d) => d.id), [devV.id]);

  const channel = t.store.getNotification(ch.id);
  const alert = (monitorId, name) => ({
    kind: 'down', title: `Alert: ${name} is unreachable`, message: '', time: Date.now(),
    monitor: { id: monitorId, name }, affected: monitorId === core ? [{ id: cam, name: 'Cam', depth: 1 }, { id: nas, name: 'NAS', depth: 1 }] : [],
    facts: [{ key: 'reason', label: 'Reason', value: 'No reply' }],
  });
  const got = () => t.service.requests.splice(0).map((r) => ({ to: r.url, ...(r.url.endsWith('alex') ? pa : pv).decrypt(r.init.body), auth: r.init.headers.Authorization }));

  // the core is upstream of the viewer's camera: both hear, the viewer without the NAS
  let [res] = await deliver([channel], alert(core, 'Core'), { retries: [] });
  assert.equal(res.ok, true);
  let sent = got();
  assert.deepEqual(sent.map((x) => [x.to.split('/').pop(), x.body]).sort(), [['alex', 'No reply · 2 downstream affected'], ['vic', 'No reply · 1 downstream affected']]);
  assert.match(sent[0].auth, /^vapid t=.+, k=/);
  assert.equal(JSON.parse(Buffer.from(sent[0].auth.split('.')[1], 'base64url')).sub, 'https://uk.example.com');
  // the NAS isn't the viewer's: only the admin hears
  [res] = await deliver([channel], alert(nas, 'NAS'), { retries: [] });
  assert.deepEqual(got().map((x) => x.to.split('/').pop()), ['alex']);

  // A failing device is tried again on its own; the other isn't sent twice.
  t.service.status.set('https://web.push.apple.com/vic', 503);
  const a2 = alert(core, 'Core');
  const tries = [];
  const p = deliver([channel], a2, { retries: [1], sleep: async () => { tries.push(t.service.requests.map((r) => r.url.split('/').pop()).sort()); t.service.status.delete('https://web.push.apple.com/vic'); } });
  [res] = await p;
  assert.deepEqual([res.ok, res.tries], [true, 2]);
  assert.deepEqual(tries, [['alex', 'vic']]);
  assert.deepEqual(t.service.requests.splice(0).map((r) => r.url.split('/').pop()).sort(), ['alex', 'vic', 'vic']);

  // A device the push service no longer knows is forgotten.
  t.service.status.set('https://web.push.apple.com/vic', 410);
  [res] = await deliver([channel], alert(core, 'Core'), { retries: [] });
  assert.equal(res.ok, true);
  assert.equal(t.store.getPushDevice(devV.id), null);
  t.service.requests.length = 0;

  // A refusal is reported, and kept on the device for its owner to see.
  t.service.status.set('https://web.push.apple.com/alex', 403);
  [res] = await deliver([channel], alert(core, 'Core'), { retries: [5] });
  assert.equal(res.ok, false);
  assert.match(res.error, /Alex iPhone: HTTP 403/);
  assert.match((await admin.call('GET', '/api/webpush')).devices[0].lastError, /403/);
  t.service.status.delete('https://web.push.apple.com/alex');
  t.service.requests.length = 0;

  // Send test on the channel form, and on one device.
  await admin.call('POST', '/api/notifications/test', { id: ch.id, name: 'Phones', type: 'webpush', config: {} });
  assert.equal(got()[0].title, 'Test: Upstream Kuma is flowing');
  await assert.rejects(admin.call('POST', '/api/notifications/test', { name: 'New', type: 'webpush', config: {} }), /Save the channel/);
  await admin.call('POST', `/api/webpush/devices/${devA.id}/test`);
  assert.equal(got()[0].body, 'Push notifications work on this device.');

  // Changing what a device wants; signing out forgets it; no devices is an error.
  assert.deepEqual((await admin.call('PUT', `/api/webpush/devices/${devA.id}`, { channelIds: [], name: 'Old phone' })).channelIds, []);
  await admin.call('PUT', `/api/webpush/devices/${devA.id}`, { channelIds: [ch.id] });
  await admin.call('POST', '/api/webpush/forget', { endpoint: 'https://web.push.apple.com/alex' });
  assert.equal(t.store.listPushDevices().length, 0);
  [res] = await deliver([channel], alert(core, 'Core'), { retries: [] });
  assert.match(res.error, /No device has signed up/);

  // A deleted account's devices go with it; a turned-off one hears nothing.
  const vic = t.store.listUsers().find((u) => u.username === 'vic');
  await viewer.call('POST', '/api/webpush/devices', { subscription: subscription('https://web.push.apple.com/vic', pv.keys), channelIds: [ch.id] });
  await admin.call('PUT', `/api/users/${vic.id}`, { active: false });
  [res] = await deliver([channel], alert(core, 'Core'), { retries: [] });
  assert.deepEqual([res.ok, t.service.requests.length], [true, 0]);
  await admin.call('DELETE', `/api/users/${vic.id}`);
  assert.equal(t.store.listPushDevices().length, 0);
});
