import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/db.js';
import { Engine } from '../src/engine.js';
import { Graph } from '../src/graph.js';
import { UP, DOWN, BLOCKED, PENDING } from '../src/status.js';

// Builds the hierarchy from the README:
//   WAN
//   ├ Host 1 ─ Service 1 ─ Microservice 1
//   │        └ Service 2
//   └ Host 2 ─ Service 2.1 ─ Microservice 2.1.1
//            └ Service 2.2
function setup({ retries = 0 } = {}) {
  const store = new Store(':memory:');
  let clock = 1_700_000_000_000;
  const results = {}; // monitor name -> boolean (up?)
  const calls = {};   // monitor name -> number of real checks
  const alerts = [];

  const fake = (m) => {
    calls[m.name] = (calls[m.name] ?? 0) + 1;
    const ok = results[m.name] ?? true;
    return { ok, ping: 5, msg: ok ? 'ok' : 'timeout' };
  };
  const checkers = { ping: fake, http: fake, tcp: fake };

  const notifId = store.createNotification({ name: 'phone', type: 'webhook', config: {} });
  store.createRule({ channelIds: [notifId] }); // everything, for every monitor
  const ids = {};
  const add = (name, type, parents = [], extra = {}) => {
    const id = store.createMonitor({
      name, type, config: {}, interval: 60, retries, retryInterval: 20, timeout: 5,
      resendInterval: 0, parentMode: 'all', active: true, ...extra,
    });
    for (const p of parents) store.addEdge(ids[p], id);
    ids[name] = id;
  };
  add('WAN', 'ping');
  add('Host 1', 'ping', ['WAN']);
  add('Service 1', 'http', ['Host 1']);
  add('Microservice 1', 'http', ['Service 1']);
  add('Service 2', 'http', ['Host 1']);
  add('Host 2', 'ping', ['WAN']);
  add('Service 2.1', 'http', ['Host 2']);
  add('Microservice 2.1.1', 'http', ['Service 2.1']);
  add('Service 2.2', 'http', ['Host 2']);

  const engine = new Engine({
    store,
    checkers,
    notify: async (channels, alert) => {
      alerts.push(alert);
      return channels.map((c) => ({ id: c.id, ok: true }));
    },
    now: () => clock,
    schedule: () => null,
    cancel: () => {},
  });
  const status = (name) => engine.runtime.get(ids[name]).status;
  const advance = (ms) => { clock += ms; };
  const resetCalls = () => { for (const k of Object.keys(calls)) delete calls[k]; };
  return { store, engine, ids, results, calls, alerts, status, advance, resetCalls, add };
}

test('a down host sends one alert listing everything beneath it, without checking it', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();

  assert.equal(t.status('Host 2'), DOWN);
  for (const n of ['Service 2.1', 'Microservice 2.1.1', 'Service 2.2']) {
    assert.equal(t.status(n), BLOCKED, `${n} should be blocked`);
    assert.equal(t.calls[n] ?? 0, 0, `${n} should never have been checked`);
  }
  assert.equal(t.status('Service 1'), UP);

  assert.equal(t.alerts.length, 1);
  const [a] = t.alerts;
  assert.equal(a.title, 'Alert: Host 2 is unreachable');
  assert.match(a.message, /Other affected monitors \(3\):\n- Service 2\.1\n-- Microservice 2\.1\.1\n- Service 2\.2/);
  assert.deepEqual(a.affected.map((x) => x.name), ['Service 2.1', 'Microservice 2.1.1', 'Service 2.2']);
  // the same details, structured, for providers that lay them out (Google Chat)
  assert.deepEqual(a.facts.map((f) => f.key), ['reason', 'time']);
  assert.equal(a.facts[0].value, 'timeout');
  assert.deepEqual(a.upstream, ['WAN']);
  assert.equal(a.url, null); // no public address set
});

test('alerts link to the monitor once the public address is set', async () => {
  const t = setup();
  t.store.setSettings({ publicUrl: 'https://uk.example.com' });
  t.results['Microservice 2.1.1'] = false;
  await t.engine.start();
  await t.engine.idle();
  const [a] = t.alerts;
  assert.deepEqual(a.upstream, ['WAN', 'Host 2', 'Service 2.1']);
  assert.equal(a.url, `https://uk.example.com/#/?focus=${t.ids['Microservice 2.1.1']}&info=${t.ids['Microservice 2.1.1']}`);
});

test('a child failure re-checks its parents first and alerts on the real root cause', async () => {
  const t = setup();
  await t.engine.start();
  t.advance(60_000);
  t.resetCalls();

  // WAN dies, but Host 2's timer happens to fire before WAN's does.
  t.results.WAN = false;
  t.results['Host 2'] = false;
  await t.engine.check(t.ids['Host 2']);
  await t.engine.idle();

  assert.equal(t.calls.WAN, 1, 'WAN should be probed by the failing child');
  assert.equal(t.status('WAN'), DOWN);
  assert.equal(t.status('Host 2'), BLOCKED);
  assert.equal(t.status('Microservice 1'), BLOCKED);
  assert.equal(t.alerts.length, 1, 'only the root cause alerts');
  assert.equal(t.alerts[0].title, 'Alert: WAN is unreachable');
  assert.equal(t.alerts[0].affected.length, 8);
});

test('a failing parent that is still retrying holds the child in pending', async () => {
  const t = setup({ retries: 1 });
  await t.engine.start();
  t.advance(60_000);

  t.results['Host 1'] = false;
  t.results['Service 1'] = false;
  await t.engine.check(t.ids['Service 1']); // pending (retry 1/1)
  t.advance(20_000);
  await t.engine.check(t.ids['Service 1']); // confirmed failure -> probes Host 1 (now pending)
  assert.equal(t.status('Host 1'), PENDING);
  assert.equal(t.status('Service 1'), PENDING);
  assert.equal(t.alerts.length, 0);

  t.advance(20_000);
  await t.engine.check(t.ids['Host 1']);
  await t.engine.idle();
  assert.equal(t.status('Host 1'), DOWN);
  assert.equal(t.status('Service 1'), BLOCKED);
  assert.deepEqual(t.alerts.map((a) => a.title), ['Alert: Host 1 is unreachable']);
});

test('recovery sends a resolved alert and re-checks downstream one level at a time', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();
  t.advance(5 * 60_000);
  t.resetCalls();

  t.results['Host 2'] = true;
  t.results['Service 2.1'] = false;
  await t.engine.check(t.ids['Host 2']);
  await t.engine.idle();

  assert.equal(t.status('Host 2'), UP);
  assert.equal(t.status('Service 2.2'), UP);
  assert.equal(t.status('Service 2.1'), DOWN);
  assert.equal(t.status('Microservice 2.1.1'), BLOCKED);
  assert.equal(t.calls['Microservice 2.1.1'] ?? 0, 0);

  const titles = t.alerts.map((a) => a.title);
  assert.deepEqual(titles, [
    'Alert: Host 2 is unreachable',
    'Resolved: Host 2 is back up',
    'Alert: Service 2.1 is down',
  ]);
  assert.match(t.alerts[1].message, /after 5m 0s down/);
  assert.deepEqual(t.alerts[2].affected.map((a) => a.name), ['Microservice 2.1.1']);
});

test('a monitor blocked after its own down alert still sends a resolved one', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();
  t.advance(10 * 60_000);
  // then its parent goes down too: Host 2 is blocked, not down
  t.results.WAN = false;
  await t.engine.check(t.ids.WAN);
  await t.engine.idle();
  assert.equal(t.status('Host 2'), BLOCKED);
  t.advance(5 * 60_000);
  // both come back
  t.results.WAN = true;
  t.results['Host 2'] = true;
  await t.engine.check(t.ids.WAN);
  await t.engine.idle();
  assert.equal(t.status('Host 2'), UP);
  assert.deepEqual(t.alerts.map((a) => a.title), [
    'Alert: Host 2 is unreachable',
    'Alert: WAN is unreachable',
    'Resolved: WAN is back up',
    'Resolved: Host 2 is back up',
  ]);
  assert.match(t.alerts[3].message, /after 15m 0s down/); // since its own down alert
  // and only once: the next check is an ordinary up
  await t.engine.check(t.ids['Host 2']);
  await t.engine.idle();
  assert.equal(t.alerts.length, 4);
});

test('a resolved alert goes wherever the down alert went', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();
  const phone = t.store.listNotifications()[0].id;
  assert.deepEqual(t.store.listAlerts(1)[0].delivered.map((d) => d.id), [phone]);
  // the rule that sent it is gone (or no longer matches): the resolved alert
  // still follows the down alert
  for (const r of t.store.listRules()) t.store.deleteRule(r.id);
  t.results['Host 2'] = true;
  await t.engine.check(t.ids['Host 2']);
  await t.engine.idle();
  const up = t.store.listAlerts(1)[0];
  assert.equal(up.kind, 'up');
  assert.deepEqual(up.delivered.map((d) => d.id), [phone]);
});

test('an alert is logged before it is sent, and updated when the send is done', async () => {
  const t = setup();
  let finish;
  t.engine.notify = (channels) => new Promise((resolve) => { finish = () => resolve(channels.map((c) => ({ id: c.id, name: c.name, ok: true, tries: 2 }))); });
  t.results['Host 2'] = false;
  await t.engine.start();
  const v = t.engine.version;
  assert.deepEqual(t.store.listAlerts(1)[0].delivered, [{ id: 1, name: 'phone', pending: true }]);
  finish();
  await t.engine.idle();
  assert.deepEqual(t.store.listAlerts(1)[0].delivered, [{ id: 1, name: 'phone', ok: true, tries: 2 }]);
  assert.ok(t.engine.version > v, 'the page hears about it');
});

test('after a restart, a resolved alert counts from the down alert', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();
  for (let i = 0; i < 5; i++) {
    t.advance(60_000);
    await t.engine.check(t.ids['Host 2']);
  }
  let clock = t.engine.now() + 60_000;
  const again = new Engine({
    store: t.store,
    checkers: t.engine.checkers,
    notify: async (c, a) => { t.alerts.push(a); return []; },
    now: () => clock,
    schedule: () => null,
    cancel: () => {},
  });
  t.results['Host 2'] = true;
  await again.start();
  await again.idle();
  assert.equal(t.alerts.at(-1).title, 'Resolved: Host 2 is back up');
  assert.match(t.alerts.at(-1).message, /after 6m 0s down/);
});

test("parentMode 'any' keeps a monitor reachable while one parent is up", async () => {
  const t = setup();
  t.add('Shared NAS', 'tcp', ['Host 1', 'Host 2'], { parentMode: 'any' });
  t.add('Strict NAS', 'tcp', ['Host 1', 'Host 2']);
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();

  assert.equal(t.status('Shared NAS'), UP);
  assert.equal(t.status('Strict NAS'), BLOCKED);
  assert.ok(!t.alerts[0].affected.some((a) => a.name === 'Shared NAS'));
  assert.ok(t.alerts[0].affected.some((a) => a.name === 'Strict NAS'));
});

test('groups are transparent folders', async () => {
  const t = setup();
  t.add('Media', 'group', ['Host 1']);
  t.add('Plex', 'http', ['Media']);
  await t.engine.start();
  t.advance(60_000);
  t.results['Host 1'] = false;
  await t.engine.check(t.ids['Host 1']);
  await t.engine.idle();

  assert.equal(t.status('Plex'), BLOCKED);
  assert.equal(t.engine.displayStatus(t.ids.Media), 'blocked');
  const affected = t.alerts[0].affected.map((a) => `${a.depth}:${a.name}`);
  assert.ok(affected.includes('1:Media') && affected.includes('2:Plex'));
});

test('a paused parent does not block its children', async () => {
  const t = setup();
  t.store.updateMonitor(t.ids['Host 1'], { active: false });
  t.results['Host 1'] = false;
  await t.engine.start();
  await t.engine.idle();
  assert.equal(t.calls['Host 1'] ?? 0, 0);
  assert.equal(t.status('Service 1'), UP);
});

test('restarting while something is already down does not re-alert', async () => {
  const t = setup();
  t.results['Host 2'] = false;
  await t.engine.start();
  await t.engine.idle();
  assert.equal(t.alerts.length, 1);

  const again = new Engine({
    store: t.store,
    checkers: t.engine.checkers,
    notify: async (c, a) => { t.alerts.push(a); return []; },
    schedule: () => null,
    cancel: () => {},
  });
  await again.start();
  await again.idle();
  assert.equal(t.alerts.length, 1);
});

test('push monitors go up on push and down when pushes stop', async () => {
  const t = setup();
  t.add('Backup job', 'push', ['Host 1']);
  await t.engine.start();
  assert.equal(t.status('Backup job'), DOWN);
  const token = t.store.getMonitor(t.ids['Backup job']).pushToken;
  await t.engine.receivePush(token, {});
  await t.engine.idle();
  assert.equal(t.status('Backup job'), UP);
  t.advance(61_000);
  await t.engine.check(t.ids['Backup job']);
  assert.equal(t.status('Backup job'), DOWN);
});

test('graph rejects cycles', () => {
  const g = new Graph([1, 2, 3], [{ parentId: 1, childId: 2 }, { parentId: 2, childId: 3 }]);
  assert.equal(g.wouldCycle(3, 1), true);
  assert.equal(g.wouldCycle(1, 3), false);
  assert.equal(new Graph([1, 2], [{ parentId: 1, childId: 2 }, { parentId: 2, childId: 1 }]).hasCycle(), true);
});

// ---- the check queue ----

// Checks that finish when told to: `running` lists the names being checked.
function slowSetup(concurrency) {
  const store = new Store(':memory:');
  const running = [];
  const finish = new Map();
  const slow = (m) => new Promise((resolve) => {
    running.push(m.name);
    finish.set(m.name, () => {
      running.splice(running.indexOf(m.name), 1);
      resolve({ ok: true, ping: 1, msg: 'ok' });
    });
  });
  const ids = {};
  const add = (name, type = 'ping', parents = []) => {
    ids[name] = store.createMonitor({ name, type, config: {}, interval: 60, retries: 0, retryInterval: 20, timeout: 5, resendInterval: 0, parentMode: 'all', active: true });
    for (const p of parents) store.addEdge(ids[p], ids[name]);
  };
  const delays = [];
  const engine = new Engine({
    store, checkers: { ping: slow, snmp: slow }, notify: async () => [], concurrency, jitter: () => 1,
    schedule: (fn, ms) => { delays.push(ms); return null; }, cancel: () => {},
  });
  const tick = () => new Promise((r) => setImmediate(r));
  return { store, engine, ids, add, running, finish: async (name) => { finish.get(name)(); await tick(); await tick(); }, tick, delays };
}

test('only so many checks run at once; urgent ones go first', async () => {
  const t = slowSetup({ snmp: 1, other: 2 });
  for (const n of ['A', 'B', 'C', 'D']) t.add(n);
  t.add('S1', 'snmp');
  t.add('S2', 'snmp');
  t.engine.reload();
  for (const n of ['A', 'B', 'C', 'S1', 'S2']) t.engine.check(t.ids[n]);
  await t.tick();
  assert.deepEqual(t.running, ['A', 'B', 'S1']); // SNMP has its own, smaller pool
  assert.deepEqual(t.engine.queued, { snmp: 1, other: 1 });
  // Check now on D overtakes C, which was only routine
  t.engine.refresh(t.ids.D);
  await t.finish('A');
  assert.deepEqual(t.running, ['B', 'S1', 'D']);
  await t.finish('B');
  assert.deepEqual(t.running, ['S1', 'D', 'C']);
  await t.finish('S1');
  assert.deepEqual(t.running, ['D', 'C', 'S2']);
  for (const n of ['D', 'C', 'S2']) await t.finish(n);
  assert.deepEqual(t.engine.queued, { snmp: 0, other: 0 });
  // the next check is the interval give or take 5%
  assert.equal(t.delays.at(-1), 63000);
});

test('a check whose parent went down while it waited is blocked, not run', async () => {
  const t = slowSetup({ other: 1 });
  t.add('Router');
  t.add('Box', 'ping', ['Router']);
  t.add('Other');
  t.engine.reload();
  t.engine.check(t.ids.Other);
  t.engine.check(t.ids.Box); // waits for Other
  await t.tick();
  t.engine.runtime.get(t.ids.Router).status = DOWN; // meanwhile
  await t.finish('Other');
  assert.deepEqual(t.running, []);
  assert.equal(t.engine.runtime.get(t.ids.Box).status, BLOCKED);
});

test('an edit or Check now while a check is running gets a check of its own', async () => {
  const t = slowSetup({ other: 4 });
  t.add('Box');
  t.engine.reload();
  t.engine.check(t.ids.Box); // with the old address, say
  await t.tick();
  assert.deepEqual(t.running, ['Box']);
  t.engine.refresh(t.ids.Box); // the edit
  t.engine.refresh(t.ids.Box); // and Check now: still just one more
  await t.finish('Box');
  assert.deepEqual(t.running, ['Box'], 'checked again, from now');
  await t.finish('Box');
  assert.deepEqual(t.running, []);
});
