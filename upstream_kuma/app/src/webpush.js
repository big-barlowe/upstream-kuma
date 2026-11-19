// Web Push: notifications to phones and browsers that signed up, including an
// iPhone's home-screen app (iOS 16.4+). No dependency: the payload is
// encrypted as RFC 8291 (aes128gcm, RFC 8188) and the request signed with
// VAPID (RFC 8292), both with node:crypto.
//
// A "Web push" channel is an ordinary channel (rules route alerts to it);
// devices sign themselves up to channels from Settings → Account (table
// `push_devices`, one row per browser subscription, owned by an account). A
// viewer's devices only hear about monitors the viewer can see.
import crypto from 'node:crypto';
import { log } from './config.js';
import { level } from './notifier.js';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const TIMEOUT = 20000;
const TTL = 24 * 3600; // a phone that's off for a day misses the alert
const RECORD = 4096;
export const MAX_PAYLOAD = 3000; // well inside a record, and every service's limit

// Push services a browser may hand us. The server posts to whatever endpoint
// a device registers, and viewers register devices too, so anything else
// (an address inside your network) is refused.
const SERVICES = [/\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /\.notify\.windows\.com$/];
export function pushServiceOk(endpoint) {
  try {
    const u = new URL(endpoint);
    return u.protocol === 'https:' && SERVICES.some((re) => re.test(u.hostname));
  } catch {
    return false;
  }
}

export function vapidKeys() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return { publicKey: b64u(ecdh.getPublicKey()), privateKey: b64u(ecdh.getPrivateKey()) };
}

// The Authorization header for one push service: a JWT signed with our key.
// `sub` is how the service can reach whoever runs this (a mailto: or https:
// URL; Apple insists): the address the device signed up at.
export function vapidHeader(endpoint, { publicKey, privateKey }, sub, now = Date.now()) {
  const pub = Buffer.from(publicKey, 'base64url');
  const key = crypto.createPrivateKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', d: privateKey, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) },
  });
  const enc = (o) => b64u(JSON.stringify(o));
  const data = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({ aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + 12 * 3600, sub })}`;
  const sig = crypto.sign('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${data}.${b64u(sig)}, k=${publicKey}`;
}

const hkdf = (salt, ikm, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));

// Encrypt `payload` (a Buffer) for one subscription's keys: one aes128gcm
// record with a fresh ephemeral key and salt.
export function encrypt(payload, { p256dh, auth }) {
  const uaPublic = Buffer.from(p256dh, 'base64url');
  const authSecret = Buffer.from(auth, 'base64url');
  if (uaPublic.length !== 65 || authSecret.length < 16) throw new Error('The device\'s push keys are not valid');
  const ecdh = crypto.createECDH('prime256v1');
  const asPublic = ecdh.generateKeys();
  const shared = ecdh.computeSecret(uaPublic);
  const ikm = hkdf(authSecret, shared, Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]), 32);
  const salt = crypto.randomBytes(16);
  const cek = hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  // 0x02: the last (and only) record, no padding
  const body = Buffer.concat([cipher.update(Buffer.concat([payload, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);
  const header = Buffer.alloc(21);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD, 16);
  header[20] = asPublic.length;
  return Buffer.concat([header, asPublic, body]);
}

const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

// What a phone shows for an alert: the title, one line of what happened, and
// where tapping it goes. `visible` (a viewer's) trims the downstream count.
export function pushPayload(a, visible = null) {
  const fact = (k) => a.facts?.find((f) => f.key === k)?.value;
  const affected = (a.affected ?? []).filter((x) => !visible || visible.has(x.id));
  const back = a.kind === 'up' || a.kind === 'resolved';
  const lines = String(a.message ?? '').split('\n').map((x) => x.trim()).filter(Boolean);
  const body = [
    fact('reason') ?? fact('value'),
    fact('duration'),
    affected.length ? `${affected.length} downstream ${back ? 'back too' : 'affected'}` : null,
  ].filter(Boolean).join(' · ') || lines.find((x) => x !== a.title) || '';
  const id = a.monitor?.id;
  const payload = {
    title: cut(String(a.title ?? 'Upstream Kuma'), 200),
    body: cut(String(body), 600),
    // a hash route, opened by the service worker in the app
    url: id ? `#/?focus=${id}&info=${id}` : '#/',
    // one notification per monitor: its "back up" replaces its "down"
    tag: id ? `monitor-${id}` : `test-${Date.now()}`,
    kind: a.kind,
    level: level(a),
    time: a.time ?? Date.now(),
  };
  return payload;
}

export class WebPush {
  // `viewFor(user)`: a viewer's scopeView (null for admins). `fetch` is
  // injectable for tests.
  constructor({ store, viewFor, fetch = globalThis.fetch, now = Date.now }) {
    this.store = store;
    this.viewFor = viewFor;
    this.fetch = fetch;
    this.now = now;
    // alert -> device ids it has reached, so a retry of the channel only
    // goes to the devices that missed it
    this.reached = new WeakMap();
  }

  // Our key pair, made the first time it's needed. Changing it would
  // orphan every device's subscription.
  keys() {
    let k = this.store.getSetting('webpush');
    if (!k?.publicKey || !k?.privateKey) {
      k = vapidKeys();
      this.store.setSetting('webpush', k);
    }
    return k;
  }

  // One push to one device. Throws with `gone` (the subscription has
  // expired or been removed: forget the device) or `permanent` (refused).
  async sendTo(device, payload) {
    const keys = this.keys();
    const body = encrypt(Buffer.from(JSON.stringify(payload)), device);
    let res;
    try {
      res = await this.fetch(device.endpoint, {
        method: 'POST',
        headers: {
          Authorization: vapidHeader(device.endpoint, keys, device.origin.startsWith('https:') ? device.origin : 'mailto:upstream-kuma@example.invalid', this.now()),
          'Content-Encoding': 'aes128gcm',
          'Content-Type': 'application/octet-stream',
          TTL: String(TTL),
          Urgency: payload.level === 'urgent' ? 'high' : 'normal',
          Topic: payload.tag.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32),
        },
        body,
        signal: AbortSignal.timeout(TIMEOUT),
      });
    } catch (err) {
      const host = new URL(device.endpoint).host;
      throw new Error(err.name === 'TimeoutError' ? `No answer from ${host}` : `Couldn't reach ${host}: ${err.cause?.code ?? err.message}`);
    }
    const text = await res.text().catch(() => '');
    if (res.ok) return;
    const message = `HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ''}`;
    if (res.status === 404 || res.status === 410) throw Object.assign(new Error(message), { gone: true });
    throw Object.assign(new Error(message), { permanent: res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429 });
  }

  // Send to one device and record how it went; a gone device is deleted.
  async #deliver(device, payload) {
    try {
      await this.sendTo(device, payload);
      this.store.updatePushDevice(device.id, { lastOk: this.now(), lastError: '' });
      return { ok: true };
    } catch (err) {
      if (err.gone) {
        log.info(`Push device "${device.name}" is no longer subscribed (${err.message}); removed it`);
        this.store.deletePushDevice(device.id);
        return { ok: true, gone: true };
      }
      this.store.updatePushDevice(device.id, { lastError: err.message });
      return { ok: false, err };
    }
  }

  // A test push to one device, straight away.
  async test(device) {
    const r = await this.#deliver(device, {
      title: 'Test: Upstream Kuma is flowing',
      body: 'Push notifications work on this device.',
      url: '#/settings/account',
      tag: `test-${this.now()}`,
      kind: 'test',
      level: 'calm',
      time: this.now(),
    });
    if (r.gone) throw new Error('This device is no longer subscribed; turn notifications on again');
    if (!r.ok) throw r.err;
  }

  // The provider's send: every device signed up to the channel, each with
  // the alert as its account may see it. Throws (so `deliver()` retries)
  // only for devices that failed for a reason worth retrying.
  async sendChannel(ch, a) {
    if (!ch.id) throw Object.assign(new Error('Save the channel, then sign devices up to it in Settings → Account on each one'), { permanent: true });
    const devices = this.store.listPushDevices().filter((d) => d.channelIds.includes(ch.id));
    if (!devices.length) throw Object.assign(new Error('No device has signed up for this channel yet (Settings → Account, on each phone)'), { permanent: true });
    const reached = this.reached.get(a) ?? new Set();
    this.reached.set(a, reached);
    const views = new Map();
    const failed = [];
    let sent = 0;
    await Promise.all(devices.map(async (d) => {
      if (reached.has(d.id)) return;
      const user = this.store.getUser(d.userId);
      if (!user?.active) return reached.add(d.id);
      if (!views.has(user.id)) views.set(user.id, this.viewFor(user));
      const view = views.get(user.id);
      // a viewer hears only about monitors it can see
      if (view && a.monitor?.id && !view.visible.has(a.monitor.id)) return reached.add(d.id);
      const r = await this.#deliver(d, pushPayload(a, view?.visible ?? null));
      if (r.ok) {
        reached.add(d.id);
        if (!r.gone) sent++;
      } else {
        failed.push({ d, err: r.err });
      }
    }));
    if (!failed.length) {
      if (sent) log.info(`Pushed "${a.title}" to ${sent} device${sent === 1 ? '' : 's'} on ${ch.name}`);
      return;
    }
    const what = failed.map(({ d, err }) => `${d.name}: ${err.message}`).join('; ');
    throw Object.assign(new Error(what), { permanent: failed.every(({ err }) => err.permanent) });
  }
}
