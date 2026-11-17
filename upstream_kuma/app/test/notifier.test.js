import { test } from 'node:test';
import assert from 'node:assert/strict';
import { providers } from '../src/notifier.js';

// Captures what a provider would send; nothing leaves the machine.
async function sent(type, cfg, alert) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: JSON.parse(init.body) });
    return new Response('{}', { status: 200 });
  };
  try {
    await providers[type].send(cfg, alert);
  } finally {
    globalThis.fetch = real;
  }
  return calls;
}

const alert = { kind: 'down', title: 'Down: Router', message: 'Router is down\nReason: timeout\n\nOther affected monitors (1):\n- Switch A', monitor: { id: 1, name: 'Router' }, affected: [], time: 0 };
const CHAT = 'https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t';

test('Google Chat gets only its own message format', async () => {
  const [c] = await sent('googlechat', { webhookUrl: CHAT }, alert);
  assert.equal(c.url, CHAT);
  assert.deepEqual(c.body, { text: '*Down: Router*\n```Router is down\nReason: timeout\n\nOther affected monitors (1):\n- Switch A```' });
  // long messages are cut to fit its 4,096 characters
  const [long] = await sent('googlechat', { webhookUrl: CHAT }, { ...alert, message: 'x'.repeat(10000) });
  assert.ok(long.body.text.length <= 4096);
  assert.match(long.body.text, /…```$/);
});

test('a generic webhook pointed at Google Chat sends its format; others get the alert JSON', async () => {
  const [chat] = await sent('webhook', { url: CHAT }, alert);
  assert.deepEqual(Object.keys(chat.body), ['text']);
  const [other] = await sent('webhook', { url: 'https://example.com/hook' }, alert);
  assert.deepEqual(Object.keys(other.body), ['kind', 'title', 'message', 'time', 'monitor', 'problem', 'affected']);
});
