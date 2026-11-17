import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.js';
import { Engine } from '../src/engine.js';
import { Auth } from '../src/auth.js';
import { createApi } from '../src/api.js';

// Site
// ├ Router ─ NAS
// └ Printer
function setup() {
  const store = new Store(':memory:');
  const engine = new Engine({
    store,
    checkers: { ping: () => ({ ok: true, ping: 1, msg: 'ok' }) },
    notify: async () => [],
    schedule: () => null,
    cancel: () => {},
  });
  const icons = { describe: () => null, sync: () => {}, hasUpload: () => false, saveUpload: () => {} };
  const handle = createApi({ store, engine, icons, auth: new Auth({ store, mode: 'off' }) });
  const call = (method, path, body) => handle({ method }, new URL(`http://x${path}`), body);
  const ids = {};
  const add = (name, parent) => {
    ids[name] = store.createMonitor({
      name, type: 'ping', config: { host: name }, interval: 60, retries: 0, retryInterval: 20,
      timeout: 5, resendInterval: 0, parentMode: 'all', active: true,
    });
    if (parent) store.addEdge(ids[parent], ids[name]);
  };
  add('Site');
  add('Router', 'Site');
  add('NAS', 'Router');
  add('Printer', 'Site');
  engine.reload();
  const tagsOf = async (name) => {
    const s = await call('GET', '/api/state');
    const names = new Map(s.tags.map((t) => [t.id, t.name]));
    return s.monitors.find((m) => m.id === ids[name]).tags.map((t) => names.get(t));
  };
  return { store, engine, call, ids, tagsOf };
}

test('tags are validated and names are unique regardless of case', async () => {
  const { call } = setup();
  const t = await call('POST', '/api/tags', { name: '  Home   lab ', color: '#38BDF8' });
  assert.deepEqual(t, { id: t.id, name: 'Home lab', color: '#38bdf8', icon: '', iconV: 0 });
  await assert.rejects(call('POST', '/api/tags', { name: 'home LAB', color: '#ffffff' }), /already a tag called "Home lab"/);
  await assert.rejects(call('POST', '/api/tags', { name: 'x', color: 'red' }), /colour/);
  await assert.rejects(call('POST', '/api/tags', { name: ' ', color: '#ffffff' }), /required/);
  await assert.rejects(call('POST', '/api/tags', { name: 'a|b', color: '#ffffff' }), /cannot contain/);
  // renaming to its own name in another case is fine
  assert.equal((await call('PUT', `/api/tags/${t.id}`, { name: 'HOME LAB' })).name, 'HOME LAB');
});

test('applying to a selection can include everything downstream, and so can removing', async () => {
  const { call, ids, tagsOf } = setup();
  const site = await call('POST', '/api/tags', { name: 'Site A', color: '#a78bfa' });
  const res = await call('POST', `/api/tags/${site.id}/apply`, { monitorIds: [ids.Router], downstream: true });
  assert.deepEqual(res, { ok: true, changed: 2, monitors: 2 });
  assert.deepEqual(await tagsOf('NAS'), ['Site A']);
  assert.deepEqual(await tagsOf('Printer'), []);

  await call('POST', `/api/tags/${site.id}/apply`, { monitorIds: [ids.Site], downstream: true });
  assert.deepEqual(await tagsOf('Printer'), ['Site A']);

  await call('POST', `/api/tags/${site.id}/apply`, { monitorIds: [ids.Router], downstream: true, remove: true });
  assert.deepEqual(await tagsOf('NAS'), []);
  assert.deepEqual(await tagsOf('Site'), ['Site A']);

  const tags = await call('GET', '/api/tags');
  assert.equal(tags[0].count, 2);
});

test('saving a monitor sets its tags and can pass new ones downstream', async () => {
  const { call, ids, tagsOf, engine } = setup();
  const a = await call('POST', '/api/tags', { name: 'Prod', color: '#fb923c' });
  const b = await call('POST', '/api/tags', { name: 'Network', color: '#60a5fa' });
  await call('PUT', `/api/monitors/${ids.NAS}`, { tagIds: [a.id] });

  await call('PUT', `/api/monitors/${ids.Site}`, { tagIds: [b.id], tagsDownstream: true });
  assert.deepEqual(await tagsOf('Site'), ['Network']);
  assert.deepEqual(await tagsOf('NAS'), ['Prod', 'Network']); // kept its own tag (in tag order)

  // Only newly added tags travel: re-saving with the same tags doesn't
  // re-tag a dependent that had it removed.
  await call('PUT', `/api/monitors/${ids.Printer}`, { tagIds: [] });
  await call('PUT', `/api/monitors/${ids.Site}`, { tagIds: [b.id], tagsDownstream: true });
  assert.deepEqual(await tagsOf('Printer'), []);

  // Leaving tagIds out leaves the tags alone.
  await call('PUT', `/api/monitors/${ids.Site}`, { name: 'Site 1' });
  assert.deepEqual(await tagsOf('Site'), ['Network']);
  assert.deepEqual((await call('GET', `/api/monitors/${ids.Site}`)).tagIds, [b.id]);

  await assert.rejects(call('PUT', `/api/monitors/${ids.Site}`, { tagIds: [999] }), /Unknown tag/);

  // Deleting a tag takes it off every monitor and bumps the state version.
  const v = engine.version;
  await call('DELETE', `/api/tags/${b.id}`);
  assert.ok(engine.version > v);
  assert.deepEqual(await tagsOf('NAS'), ['Prod']);
});

test('a tag can carry a default icon, uploaded or not', async () => {
  const { call, store } = setup();
  const png = 'data:image/png;base64,' + Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]).toString('base64');
  const t = await call('POST', '/api/tags', { name: 'Switch', color: '#60a5fa', icon: 'builtin:switch' });
  assert.equal(t.icon, 'builtin:switch');
  await assert.rejects(call('PUT', `/api/tags/${t.id}`, { icon: 'none' }), /can’t be "none"/);
  await assert.rejects(call('PUT', `/api/tags/${t.id}`, { icon: 'upload' }), /Choose an image/);
  const up = await call('PUT', `/api/tags/${t.id}`, { icon: 'upload', iconData: png });
  assert.ok(up.iconV > 0);
  const img = await call('GET', `/api/tags/${t.id}/icon`);
  assert.equal(img.headers['Content-Security-Policy'].includes('sandbox'), true);
  // keeping 'upload' without a new image keeps the old one; renaming leaves it
  await call('PUT', `/api/tags/${t.id}`, { name: 'Switches', icon: 'upload' });
  assert.ok(store.getTagIcon(t.id));
  await call('PUT', `/api/tags/${t.id}`, { icon: '' });
  await assert.rejects(call('GET', `/api/tags/${t.id}/icon`), /No icon/);
});

test('tags have an order: new ones go last, and reordering changes whose icon a monitor gets', async () => {
  const { call, ids, store } = setup();
  const b = await call('POST', '/api/tags', { name: 'B', color: '#a78bfa', icon: 'builtin:bolt:#FACC15' });
  const a = await call('POST', '/api/tags', { name: 'A', color: '#60a5fa', icon: 'builtin:server' });
  assert.equal(b.icon, 'builtin:bolt:#facc15');
  const names = async () => (await call('GET', '/api/tags')).map((t) => t.name);
  assert.deepEqual(await names(), ['B', 'A']);
  await call('PUT', `/api/monitors/${ids.NAS}`, { ...store.getMonitor(ids.NAS), tagIds: [a.id, b.id] });
  const { tagIconSpecs } = await import('../src/icons.js');
  const iconOf = () => tagIconSpecs(store.listTags(), store.monitorTagMap()).get(ids.NAS);
  assert.equal(iconOf(), 'builtin:bolt:#facc15');

  // Listed ids come first; any left out keep their order after them.
  const c = await call('POST', '/api/tags', { name: 'C', color: '#22d3ee' });
  assert.deepEqual((await call('POST', '/api/tags/order', { ids: [a.id] })).map((t) => t.name), ['A', 'B', 'C']);
  assert.equal(iconOf(), 'builtin:server');
  assert.deepEqual(store.monitorTagMap().get(ids.NAS), [a.id, b.id]);
  await call('POST', '/api/tags/order', { ids: [c.id, b.id, a.id] });
  assert.deepEqual(await names(), ['C', 'B', 'A']);
  assert.equal(iconOf(), 'builtin:bolt:#facc15');
  await assert.rejects(call('POST', '/api/tags/order', { ids: [999] }), /Unknown tag/);
  await assert.rejects(call('POST', '/api/tags/order', {}), /list of tag ids/);
});

test('upgrading keeps tags in name order', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { DatabaseSync } = await import('node:sqlite');
  const { MIGRATIONS } = await import('../src/db.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uk-tags-'));
  const file = path.join(dir, 'db.sqlite');
  try {
    const db = new DatabaseSync(file);
    for (let v = 0; v < 8; v++) (typeof MIGRATIONS[v] === 'function' ? MIGRATIONS[v](db) : db.exec(MIGRATIONS[v]));
    db.exec('PRAGMA user_version = 8');
    for (const n of ['zebra', 'Apple', 'mango']) db.prepare("INSERT INTO tags (name, color) VALUES (?, '#000000')").run(n);
    db.close();
    const store = new Store(file);
    assert.deepEqual(store.listTags().map((t) => t.name), ['Apple', 'mango', 'zebra']);
    const id = store.createTag({ name: 'Banana', color: '#000000' });
    assert.equal(store.listTags().at(-1).id, id);
    store.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
