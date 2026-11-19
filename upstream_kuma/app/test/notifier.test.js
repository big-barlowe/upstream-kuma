import { test } from 'node:test';
import assert from 'node:assert/strict';
import { providers } from '../src/notifier.js';

// Captures what a provider would send; nothing leaves the machine. `reply`
// answers each request (a Response), so a refusal can be faked.
async function sent(type, cfg, alert, reply = () => new Response('{}', { status: 200 })) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: JSON.parse(init.body) });
    return reply(calls.length);
  };
  try {
    await providers[type].send(cfg, alert);
  } finally {
    globalThis.fetch = real;
  }
  return calls;
}

const alert = {
  kind: 'down',
  title: 'Alert: Host <2> is unreachable',
  message: 'Host <2> is unreachable.\n\nReason: timeout\n\nOther affected monitors (2):\n- Service 2.1\n-- Microservice 2.1.1',
  monitor: { id: 6, name: 'Host <2>' },
  upstream: ['WAN'],
  affected: [{ id: 7, name: 'Service 2.1', depth: 1 }, { id: 8, name: 'Microservice 2.1.1', depth: 2 }],
  facts: [{ key: 'reason', label: 'Reason', value: 'timeout' }, { key: 'time', label: 'Time', value: 'now' }],
  url: 'https://uk.example.com/#/?focus=6&info=6',
  time: 0,
};
const CHAT = 'https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t';
const refuse = (n) => (n === 1 ? new Response('{"error":{"code":400}}', { status: 400 }) : new Response('{}'));

test('Google Chat gets a card: status, details, the flow, a link', async () => {
  const [c] = await sent('googlechat', { webhookUrl: CHAT }, alert);
  assert.equal(c.url, CHAT);
  assert.equal(c.body.fallbackText, 'Alert: Host <2> is unreachable (2 downstream cut off)');
  const { card } = c.body.cardsV2[0];
  assert.equal(card.header.title, 'Host <2> is unreachable');
  assert.equal(card.header.subtitle, 'Upstream Kuma · Alert');
  const [details, flow, link] = card.sections;
  assert.deepEqual(details.widgets.map((w) => w.decoratedText.topLabel), ['Status', 'Reason', 'Time']);
  assert.match(details.widgets[0].decoratedText.text, /DOWN.*2 downstream cut off/);
  // the flow: what is above, the monitor (names escaped), what it cut off
  const lines = flow.widgets[0].textParagraph.text.split('<br>').map((l) => l.replace(/<[^>]+>/g, ''));
  assert.deepEqual(lines.map((l) => l.trim()), ['● WAN', '└ ● Host &lt;2&gt; DOWN', '└ ● Service 2.1', '└ ● Microservice 2.1.1']);
  assert.ok(lines[3].indexOf('└') > lines[2].indexOf('└'), 'deeper monitors are indented further');
  assert.equal(link.widgets[0].buttonList.buttons[0].onClick.openLink.url, alert.url);
  // no address, no button; a long tree folds
  const many = Array.from({ length: 60 }, (_, i) => ({ id: i, name: `M${i}`, depth: 1 }));
  const [c2] = await sent('googlechat', { webhookUrl: CHAT }, { ...alert, url: null, affected: many });
  const sections = c2.body.cardsV2[0].card.sections;
  assert.equal(sections.length, 2);
  assert.equal(sections[1].collapsible, true);
  assert.match(sections[1].widgets[1].textParagraph.text, /and 20 more/);
});

test('if Google Chat refuses the card, a real alert goes as text; a test shows why', async () => {
  const calls = await sent('googlechat', { webhookUrl: CHAT }, alert, refuse);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].body.cardsV2);
  assert.match(calls[1].body.text, /^\*Alert: Host <2> is unreachable\*\n```Host <2> is unreachable\./);
  await assert.rejects(sent('googlechat', { webhookUrl: CHAT }, { ...alert, kind: 'test' }, refuse), /HTTP 400/);
});

test('a generic webhook pointed at Google Chat sends its format; others get the alert JSON', async () => {
  const [chat] = await sent('webhook', { url: CHAT }, alert);
  assert.ok(chat.body.cardsV2);
  const [other] = await sent('webhook', { url: 'https://example.com/hook' }, alert);
  assert.deepEqual(Object.keys(other.body), ['kind', 'title', 'message', 'time', 'monitor', 'problem', 'affected', 'upstream', 'facts', 'url']);
});

// ---- delivery: retries and error messages ----

import { deliver } from '../src/notifier.js';

async function delivering(replies, { retries = [5000, 30000], type = 'googlechat', cfg = { webhookUrl: CHAT } } = {}) {
  const real = globalThis.fetch;
  const waits = [];
  let n = 0;
  globalThis.fetch = async () => replies[Math.min(n++, replies.length - 1)]();
  try {
    const [res] = await deliver([{ id: 3, name: 'Chat', type, config: cfg }], alert, { retries, sleep: async (ms) => { waits.push(ms); } });
    return { res, waits, calls: n };
  } finally {
    globalThis.fetch = real;
  }
}
const timeout = () => { throw new DOMException('The operation was aborted due to timeout', 'TimeoutError'); };
const unreachable = () => { throw new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo EAI_AGAIN chat.googleapis.com'), { code: 'EAI_AGAIN', hostname: 'chat.googleapis.com' }) }); };
const ok = () => new Response('{}');

test('a send that times out is tried again, and says how it went', async () => {
  let r = await delivering([timeout, ok]);
  assert.deepEqual(r.res, { id: 3, name: 'Chat', ok: true, tries: 2 });
  assert.deepEqual(r.waits, [5000]);
  r = await delivering([timeout]);
  assert.deepEqual([r.res.ok, r.res.tries, r.calls], [false, 3, 3]);
  assert.equal(r.res.error, 'No answer from chat.googleapis.com within 20s (tried 3 times)');
  r = await delivering([unreachable], { retries: [] });
  assert.equal(r.res.error, "Couldn't reach chat.googleapis.com: EAI_AGAIN (chat.googleapis.com)");
  // a busy service is worth another go too
  r = await delivering([() => new Response('slow down', { status: 429 }), () => new Response('oops', { status: 503 }), ok]);
  assert.deepEqual([r.res.ok, r.res.tries], [true, 3]);
});

test('a refusal is not retried', async () => {
  const r = await delivering([() => new Response('{"error":"bad"}', { status: 403 })], { type: 'slack', cfg: { webhookUrl: 'https://hooks.example.com/x' } });
  assert.deepEqual([r.res.ok, r.calls, r.waits], [false, 1, []]);
  assert.match(r.res.error, /^HTTP 403/);
  const missing = await delivering([ok], { type: 'slack', cfg: {} });
  assert.deepEqual([missing.res.error, missing.calls], ['Missing "webhookUrl"', 0]);
});

const back = { ...alert, kind: 'up', title: 'Resolved: Host <2> is back up' };

test('Pushover plays the alert sound or the resolved sound, and the default when unset', async () => {
  const cfg = { userKey: 'u', appToken: 't', alertSound: 'siren', resolvedSound: 'magic' };
  assert.equal((await sent('pushover', cfg, alert))[0].body.sound, 'siren');
  assert.equal((await sent('pushover', cfg, back))[0].body.sound, 'magic');
  assert.equal((await sent('pushover', { ...cfg, resolvedSound: ' ' }, back))[0].body.sound, undefined);
});

test('ntfy gives recoveries a priority of their own (the phone picks the sound by priority)', async () => {
  const cfg = { server: 'https://ntfy.example', topic: 'net' };
  let [c] = await sent('ntfy', cfg, alert);
  assert.deepEqual([c.body.priority, c.body.tags], [5, ['rotating_light']]);
  [c] = await sent('ntfy', cfg, back);
  assert.deepEqual([c.body.priority, c.body.tags], [3, ['white_check_mark']]);
  [c] = await sent('ntfy', { ...cfg, resolvedPriority: '2', priority: '9' }, back);
  assert.equal(c.body.priority, 2);
  [c] = await sent('ntfy', { ...cfg, priority: '9' }, alert);
  assert.equal(c.body.priority, 5);
});

test('Home Assistant: sounds and channels for the Companion app, critical down alerts', async () => {
  const { config } = await import('../src/config.js');
  const saved = { haUrl: config.haUrl, haToken: config.haToken };
  Object.assign(config, { haUrl: 'http://ha.test', haToken: 'x' });
  const pick = (d) => d && { channel: d.channel, ttl: d.ttl, priority: d.priority, push: d.push };
  try {
    const phone = { service: 'notify.mobile_app_iphone', alertSound: 'Alarm.caf', resolvedSound: 'Tink.caf' };
    let [c] = await sent('homeassistant', phone, alert);
    assert.equal(c.url, 'http://ha.test/api/services/notify/mobile_app_iphone');
    assert.deepEqual(pick(c.body.data), { channel: 'Upstream Kuma alerts', ttl: 0, priority: 'high', push: { sound: 'Alarm.caf' } });
    [c] = await sent('homeassistant', phone, back);
    assert.deepEqual(pick(c.body.data), { channel: 'Upstream Kuma resolved', ttl: undefined, priority: undefined, push: { sound: 'Tink.caf' } });
    [c] = await sent('homeassistant', { ...phone, critical: true }, alert);
    assert.deepEqual(pick(c.body.data), { channel: 'alarm_stream', ttl: 0, priority: 'high', push: { sound: { name: 'Alarm.caf', critical: 1, volume: 1 } } });
    // recoveries are never critical
    [c] = await sent('homeassistant', { ...phone, critical: true }, back);
    assert.equal(c.body.data.push.sound, 'Tink.caf');
    // a phone without sounds still gets its channel; other services get no data
    [c] = await sent('homeassistant', { service: 'notify.mobile_app_pixel' }, back);
    assert.deepEqual(pick(c.body.data), { channel: 'Upstream Kuma resolved', ttl: undefined, priority: undefined, push: undefined });
    [c] = await sent('homeassistant', { service: 'notify.telegram' }, alert);
    assert.equal(c.body.data, undefined);
    assert.equal(c.body.title, alert.title);
    [c] = await sent('homeassistant', { service: 'persistent_notification.create', critical: true }, alert);
    assert.equal(c.body.data, undefined);
    assert.equal(c.body.message, alert.message);
  } finally {
    Object.assign(config, saved);
  }
});

test('Home Assistant phones get the Chat card: headline, logo, the flow, and a tap that opens the monitor', async () => {
  const { config } = await import('../src/config.js');
  const saved = { haUrl: config.haUrl, haToken: config.haToken };
  Object.assign(config, { haUrl: 'http://ha.test', haToken: 'x' });
  try {
    const [c] = await sent('homeassistant', { service: 'notify.mobile_app_iphone' }, alert);
    assert.equal(c.body.title, 'Host <2> is unreachable');
    assert.equal(c.body.message, [
      '🔴 DOWN · 2 downstream cut off',
      'Reason: timeout',
      'Time: now',
      '',
      'Flow',
      '🟢 WAN',
      '└ 🔴 Host <2> · DOWN',
      '  └ ⚪ Service 2.1',
      '    └ ⚪ Microservice 2.1.1',
    ].join('\n'));
    const d = c.body.data;
    assert.equal(d.subtitle, 'Upstream Kuma · Alert');
    assert.match(d.icon_url, /icon\.png$/);
    assert.deepEqual(d.attachment, { url: d.icon_url, 'content-type': 'png' });
    assert.deepEqual([d.url, d.clickAction], [alert.url, alert.url]);
    assert.deepEqual(d.actions, [{ action: 'URI', title: 'Open in Upstream Kuma', uri: alert.url }]);
    assert.equal(d.color, '#ef4444');
    // no public address and not an add-on: nowhere to go, so no link
    const [c2] = await sent('homeassistant', { service: 'notify.mobile_app_iphone' }, { ...alert, url: null });
    assert.equal(c2.body.data.url, undefined);
    assert.equal(c2.body.data.actions, undefined);
  } finally {
    Object.assign(config, saved);
  }
});

test('the card as text is cut to fit, keeping the status, details, and the monitor', async () => {
  const { cardText } = await import('../src/notifier.js');
  const many = { ...alert, affected: Array.from({ length: 300 }, (_, i) => ({ id: i, name: `Camera ${i}`, depth: 1 })) };
  const short = cardText(many, { fits: (t) => Buffer.byteLength(t) <= 600 });
  assert.ok(Buffer.byteLength(short) <= 600);
  assert.match(short, /^🔴 DOWN · 300 downstream cut off\n/);
  assert.match(short, /└ 🔴 Host <2> · DOWN\n/);
  assert.match(short, /└ … and \d+ more$/);
  // the Chat card's limit when there's room
  assert.match(cardText(many), /… and 260 more$/);
});

test('Pushover gets the card in HTML, a link to the monitor and the alert time; ntfy the card as text, the logo and the link', async () => {
  let [c] = await sent('pushover', { userKey: 'u', appToken: 't' }, { ...alert, time: 1_700_000_000_000 });
  assert.equal(c.body.html, 1);
  assert.equal(c.body.timestamp, 1_700_000_000);
  assert.deepEqual([c.body.url, c.body.url_title], [alert.url, 'Open in Upstream Kuma']);
  assert.match(c.body.message, /^<font color="#ef4444"><b>● DOWN<\/b><\/font><font color="#94a3b8"> · 2 downstream cut off<\/font>\n<b>Reason<\/b>: timeout\n/);
  assert.match(c.body.message, /<b>Host &lt;2&gt;<\/b> <font color="#ef4444"><b>DOWN<\/b><\/font>/);
  assert.ok([...c.body.message].length <= 1024);

  [c] = await sent('ntfy', { topic: 'net' }, alert);
  assert.match(c.body.message, /^🔴 DOWN · 2 downstream cut off\n/);
  assert.match(c.body.icon, /icon\.png$/);
  assert.equal(c.body.click, alert.url);
  assert.deepEqual(c.body.actions, [{ action: 'view', label: 'Open in Upstream Kuma', url: alert.url, clear: true }]);
  [c] = await sent('ntfy', { topic: 'net' }, { ...alert, url: null });
  assert.deepEqual([c.body.click, c.body.actions], [undefined, undefined]);
});
