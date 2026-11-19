import crypto from 'node:crypto';
import { Graph } from './graph.js';
import { deliver, providerCatalog, providers, setPushSender } from './notifier.js';
import { WebPush, pushServiceOk } from './webpush.js';
import { config, isAddon, log } from './config.js';
import { decodeDataUrl } from './icons.js';
import { HttpError, badRequest, int, idList, normalizeMonitor, normalizeTag } from './validate.js';
import { exportCsv, importCsv, CSV_COLUMNS, CSV_EXAMPLE, csvTemplate } from './transfer.js';
import { DISPLAY_KEYS, snmpBrowse } from './checkers/snmp.js';
import { isOid } from './snmp.js';
import { buildLibrary, mibLibrary, parseMib, setMibLibrary, splitModules } from './mib.js';
import { parseTagExpr, renameInExpr } from '../public/js/filter.js';
import { normalizeValueProblem, inScope, SEVERITIES } from './problems.js';
import { PASSWORD_MIN, SESSION_COOKIE, clearCookie, cookie, hashPassword, parseCookies, publicUser, randomToken, scopeView, sha256, verifyPassword } from './auth.js';
import { CALLBACK_PATH, GOOGLE_DEFAULTS, GOOGLE_ISSUER, OIDC_DEFAULTS, Oidc, STATE_COOKIE, groupsOf } from './oidc.js';

// A monitor's config without the keys that only change how its data is
// shown, to tell whether what it checks has changed.
const checkedConfig = (config) => JSON.stringify(Object.fromEntries(Object.entries(config ?? {}).filter(([k]) => !DISPLAY_KEYS.includes(k))));
const displayOf = (m) => ({ oids: m.config?.oids ?? '', hide: m.config?.hide ?? [], card: m.config?.card ?? [] });
import fs from 'node:fs';

export { HttpError };

const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

// A non-JSON response (icon images).
// Icons may be SVGs from anywhere, and the add-on shares Home Assistant's
// origin, so they are served sandboxed.
const ICON_HEADERS = {
  'Cache-Control': 'private, max-age=604800',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox",
  'X-Content-Type-Options': 'nosniff',
};

export class RawResponse {
  constructor(type, body, headers = {}, status = 200) {
    this.type = type;
    this.body = body;
    this.headers = headers;
    this.status = status;
  }
}

const json = (payload, headers = {}) => new RawResponse('application/json', JSON.stringify(payload), { 'Cache-Control': 'no-store', ...headers });
// Locations are relative, so they work behind any path prefix.
const redirect = (location, headers = {}) => new RawResponse('text/plain; charset=utf-8', '', { Location: location, 'Cache-Control': 'no-store', ...headers }, 302);

// Builds the router. `ctx` = { store, engine, icons, auth, oidc?, google?,
// pushFetch? (what Web push posts with; tests fake it) }. `auth`
// (an Auth from auth.js) says who each request is; routes are for admins
// unless marked 'view' (viewers too, filtered to their scope) or 'public'.
export function createApi({ store, engine, icons, auth, oidc = new Oidc({ store }), google = new Oidc({ store, id: 'google' }), pushFetch = globalThis.fetch }) {
  if (!auth) throw new Error('createApi needs auth');
  const routes = [];
  const route = (method, pattern, handler, access = 'admin') => {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([^/]+)')) + '$');
    routes.push({ method, re, keys, handler, access });
  };

  // What a viewer may see (auth.js scopeView), or null for admins.
  const viewFor = (user) => (user.role === 'admin' ? null : scopeView(user, {
    monitorIds: engine.monitors.keys(),
    parentsOf: (id) => engine.graph.parentsOf(id),
    tagMap: store.monitorTagMap(),
    tags: store.listTags(),
  }));

  // Web push goes to each device as its account may see it.
  const webPush = new WebPush({ store, viewFor, fetch: pushFetch });
  setPushSender(webPush);

  // A monitor the request may look at: any for admins, visible ones for viewers.
  const seeMonitor = (id, view) => {
    const m = monitorOr404(id);
    if (view && !view.visible.has(m.id)) throw new HttpError(404, 'Monitor not found');
    return m;
  };

  // The MIB library: the bundled modules plus the uploaded ones. SNMP
  // monitors are checked again after a change, so card values pick up new
  // names and units.
  setMibLibrary(buildLibrary(store.listMibs()));
  const mibsChanged = () => {
    setMibLibrary(buildLibrary(store.listMibs()));
    engine.reload(store.listMonitors().filter((m) => m.type === 'snmp').map((m) => m.id));
  };

  const monitorOr404 = (id) => {
    const m = store.getMonitor(Number(id));
    if (!m) throw new HttpError(404, 'Monitor not found');
    return m;
  };

  // Replace the edges touching `id` and refuse anything that makes a loop.
  const applyEdges = (id, parentIds, childIds) => {
    let edges = store.listEdges();
    if (parentIds) edges = edges.filter((e) => e.childId !== id).concat(parentIds.map((p) => ({ parentId: p, childId: id })));
    if (childIds) edges = edges.filter((e) => e.parentId !== id).concat(childIds.map((c) => ({ parentId: id, childId: c })));
    const ids = store.listMonitors().map((m) => m.id);
    for (const e of edges) {
      if (!ids.includes(e.parentId) || !ids.includes(e.childId)) throw new HttpError(400, 'Unknown monitor in hierarchy');
      if (e.parentId === e.childId) throw new HttpError(400, 'A monitor cannot be its own parent');
    }
    if (new Graph(ids, edges).hasCycle()) {
      throw new HttpError(400, 'That would create a loop: a monitor cannot be upstream of itself');
    }
    if (parentIds) store.setParents(id, parentIds);
    if (childIds) store.setChildren(id, childIds);
  };

  // An uploaded image arrives with the monitor as a data URL in `iconData`.
  const iconUpload = (body, data, id) => {
    if (data.icon !== 'upload') return null;
    if (body.iconData) return badRequest(() => decodeDataUrl(body.iconData));
    if (id == null || !icons.hasUpload(id)) throw new HttpError(400, 'Choose an image to upload for the icon');
    return null;
  };

  const tagIdsFrom = (v) => {
    const ids = idList(v);
    if (!ids) return undefined;
    const known = new Set(store.listTags().map((t) => t.id));
    if (ids.some((t) => !known.has(t))) throw new HttpError(400, 'Unknown tag');
    return ids;
  };

  // Set a monitor's tags; with `downstream`, tags it didn't have before are
  // also added to everything below it.
  const applyMonitorTags = (id, tagIds, downstream) => {
    if (!tagIds) return;
    const before = new Set(store.monitorTagIds(id));
    store.setMonitorTags(id, tagIds);
    const added = tagIds.filter((t) => !before.has(t));
    if (!downstream || !added.length) return;
    const graph = new Graph(store.listMonitors().map((m) => m.id), store.listEdges());
    for (const d of graph.descendants(id)) for (const t of added) store.tagMonitor(d, t);
  };

  const iconsChanged = (id) => icons.sync(store.listMonitors(), id == null ? [] : [id]);

  const monitorDetail = (m) => ({
    ...m,
    parentIds: engine.graph.parentsOf(m.id),
    childIds: engine.graph.childrenOf(m.id),
    tagIds: store.monitorTagIds(m.id),
  });

  // Public: the Docker healthcheck polls it.
  route('GET', '/api/info', () => ({ version: VERSION, addon: isAddon, directAccess: config.allowDirectAccess }), 'public');

  // A viewer gets its visible monitors, with parents, children and tags
  // trimmed to what it may see, and the problems open on them.
  route('GET', '/api/state', ({ query, view }) => {
    if (query.v && Number(query.v) === engine.version) return { version: engine.version, unchanged: true };
    const snap = engine.snapshot();
    const tagMap = store.monitorTagMap();
    for (const m of snap.monitors) {
      m.icon = icons.describe(engine.monitors.get(m.id));
      m.tags = tagMap.get(m.id) ?? [];
    }
    snap.tags = store.listTags();
    snap.problems = store.listProblems().map(({ id, kind, name, severity }) => ({ id, kind, name, severity }));
    const v = view();
    if (v) {
      const seen = (id) => v.visible.has(id);
      snap.monitors = snap.monitors.filter((m) => seen(m.id));
      for (const m of snap.monitors) {
        m.parents = m.parents.filter(seen);
        m.children = m.children.filter(seen);
        m.tags = m.tags.filter((t) => v.tagIds.has(t));
      }
      snap.open = snap.open.filter((x) => seen(x.monitorId));
      const open = new Set(snap.open.map((x) => x.problemId));
      snap.problems = snap.problems.filter((p) => p.kind === 'down' || open.has(p.id));
      snap.tags = snap.tags.filter((t) => v.tagIds.has(t.id));
    }
    return snap;
  }, 'view');

  route('GET', '/api/events', ({ view }) => {
    const v = view();
    return v ? store.recentEvents(1000).filter((e) => v.visible.has(e.monitorId)).slice(0, 50) : store.recentEvents(50);
  }, 'view');

  // ---- monitors -----------------------------------------------------------

  route('GET', '/api/monitors/:id', ({ params }) => monitorDetail(monitorOr404(params.id)));

  route('POST', '/api/monitors', ({ body }) => {
    const data = normalizeMonitor(body);
    const upload = iconUpload(body, data, null);
    const parentIds = idList(body.parentIds) ?? [];
    const childIds = idList(body.childIds) ?? [];
    const tagIds = tagIdsFrom(body.tagIds);
    const id = store.tx(() => {
      const newId = store.createMonitor(data);
      applyEdges(newId, parentIds, childIds);
      applyMonitorTags(newId, tagIds, body.tagsDownstream);
      return newId;
    });
    if (upload) icons.saveUpload(id, upload);
    engine.reload([id, ...childIds]);
    iconsChanged(id);
    return monitorDetail(store.getMonitor(id));
  });

  route('PUT', '/api/monitors/:id', ({ params, body }) => {
    const existing = monitorOr404(params.id);
    const data = normalizeMonitor(body, existing);
    const upload = iconUpload(body, data, existing.id);
    const parentIds = idList(body.parentIds);
    const childIds = idList(body.childIds);
    const tagIds = tagIdsFrom(body.tagIds);
    const oldChildren = engine.graph.childrenOf(existing.id);
    store.tx(() => {
      store.updateMonitor(existing.id, data);
      // Collected data describes the old target; the next check refills it.
      if (existing.type !== data.type || checkedConfig(existing.config) !== checkedConfig(data.config)) store.clearMonitorData(existing.id);
      applyEdges(existing.id, parentIds, childIds);
      applyMonitorTags(existing.id, tagIds, body.tagsDownstream);
    });
    if (upload) icons.saveUpload(existing.id, upload);
    engine.reload([existing.id, ...oldChildren, ...(childIds ?? [])]);
    iconsChanged(existing.id);
    return monitorDetail(store.getMonitor(existing.id));
  });

  route('DELETE', '/api/monitors/:id', ({ params }) => {
    const m = monitorOr404(params.id);
    const orphans = engine.graph.childrenOf(m.id);
    store.deleteMonitor(m.id);
    engine.reload(orphans);
    iconsChanged(null);
    return { ok: true };
  });

  route('POST', '/api/monitors/:id/pause', ({ params }) => {
    const m = monitorOr404(params.id);
    store.updateMonitor(m.id, { active: false });
    engine.reload([m.id]);
    return { ok: true };
  });

  route('POST', '/api/monitors/:id/resume', ({ params }) => {
    const m = monitorOr404(params.id);
    store.updateMonitor(m.id, { active: true });
    engine.reload([m.id]);
    return { ok: true };
  });

  route('POST', '/api/monitors/:id/check', async ({ params }) => {
    const m = monitorOr404(params.id);
    await engine.refresh(m.id);
    return { ok: true };
  });

  // Drag-and-drop in the tree: move a monitor from one parent to another
  // (fromParentId/toParentId null = top level), or with link=true add the
  // new parent while keeping the old one.
  route('POST', '/api/monitors/:id/move', ({ params, body }) => {
    const m = monitorOr404(params.id);
    moveMonitors([{ id: m.id, fromParentId: body.fromParentId ?? null }], body.toParentId, body.link);
    return monitorDetail(store.getMonitor(m.id));
  });

  // The same for several monitors at once: moves = [{id, fromParentId}].
  // Without a fromParentId (selected in Flows, not under one particular
  // parent) a move replaces all of the monitor's parents. A monitor whose
  // parent is moving too stays under it, so moved subtrees keep their shape.
  route('POST', '/api/monitors/move', ({ body }) => {
    if (!Array.isArray(body.moves) || !body.moves.length) throw new HttpError(400, 'Nothing to move');
    return { ok: true, ...moveMonitors(body.moves, body.toParentId, body.link) };
  });

  const moveMonitors = (list, toParentId, link) => {
    const to = toParentId == null ? null : monitorOr404(toParentId).id;
    const moves = new Map();
    for (const mv of list) {
      const id = monitorOr404(mv?.id).id;
      moves.set(id, mv.fromParentId === undefined ? undefined : mv.fromParentId === null ? null : Number(mv.fromParentId));
    }
    if (moves.has(to)) throw new HttpError(400, 'A monitor cannot be moved under itself');
    let moved = 0;
    let along = 0;
    store.tx(() => {
      for (const [id, from] of moves) {
        let parents = engine.graph.parentsOf(id);
        if (from === undefined ? parents.some((p) => moves.has(p)) : moves.has(from)) {
          along++;
          continue;
        }
        if (!link) parents = from === undefined ? [] : parents.filter((p) => p !== from);
        if (to != null && !parents.includes(to)) parents.push(to);
        applyEdges(id, parents, undefined);
        moved++;
      }
    });
    engine.reload([...moves.keys()]);
    return { moved, along };
  };

  route('POST', '/api/edges/remove', ({ body }) => {
    store.removeEdge(Number(body.parentId), Number(body.childId));
    engine.reload([Number(body.childId)]);
    return { ok: true };
  });

  route('GET', '/api/monitors/:id/heartbeats', ({ params, query, view }) => {
    const m = seeMonitor(params.id, view());
    const hours = int(query.hours, 24, 1, 24 * 90);
    return store.heartbeatsSince(m.id, Date.now() - hours * 3600000);
  }, 'view');

  // Images come from arbitrary sites, so make sure an SVG can never run
  // script in this origin, even if someone opens the URL directly.
  route('GET', '/api/monitors/:id/icon', ({ params, view }) => {
    const icon = store.getIcon(seeMonitor(params.id, view()).id);
    if (!icon) throw new HttpError(404, 'No icon');
    return new RawResponse(icon.mime, icon.data, ICON_HEADERS);
  }, 'view');

  route('GET', '/api/monitors/:id/events', ({ params, view }) => store.importantHeartbeats(seeMonitor(params.id, view()).id, 50), 'view');

  // The latest data the monitor's checks collected (SNMP): { at, data,
  // display }, at and data null before the first. `display` holds the
  // settings for how it is shown (extra OIDs, hidden items, the card).
  route('GET', '/api/monitors/:id/data', ({ params, view }) => {
    const m = seeMonitor(params.id, view());
    return { at: null, data: null, ...store.getMonitorData(m.id), display: displayOf(m) };
  }, 'view');

  // Change how an SNMP monitor's data is shown: any of { oids, hide, card }.
  // The monitor is checked again so its card text follows.
  route('PUT', '/api/monitors/:id/snmp-display', ({ params, body }) => {
    const m = monitorOr404(params.id);
    if (m.type !== 'snmp') throw new HttpError(400, 'Not an SNMP monitor');
    const config = { ...m.config };
    for (const key of DISPLAY_KEYS) if (body?.[key] !== undefined) config[key] = body[key];
    store.updateMonitor(m.id, normalizeMonitor({ config }, m));
    engine.reload([m.id]);
    return displayOf(store.getMonitor(m.id));
  });

  // A page of everything the device reports, for the "All data" view.
  route('GET', '/api/monitors/:id/snmp/walk', async ({ params, query, view }) => {
    const m = seeMonitor(params.id, view());
    if (m.type !== 'snmp') throw new HttpError(400, 'Not an SNMP monitor');
    const start = query.start && isOid(query.start) ? query.start : undefined;
    try {
      return await snmpBrowse(m, { start, limit: int(query.limit, 2000, 50, 10000) });
    } catch (err) {
      throw new HttpError(502, err.message);
    }
  }, 'view');

  // ---- MIB library

  route('GET', '/api/mibs', () => ({ modules: mibLibrary().list() }));

  // What the MIBs know about an OID: { name, module, enums, units, desc } or null.
  route('GET', '/api/mibs/object', ({ query }) => {
    const oid = String(query.oid ?? '').trim().replace(/^\./, '');
    if (!isOid(oid)) return null;
    const hit = mibLibrary().label(oid);
    if (!hit) return null;
    const syn = hit.entry.syntax ?? {};
    return { name: hit.name, module: hit.entry.module, type: syn.tc ?? syn.base ?? null, enums: syn.enums ?? null, units: hit.entry.units ?? null, desc: hit.entry.desc ?? null };
  }, 'view');

  // { files: [{ filename, text }] }. Each module in a file is stored on its
  // own, replacing an uploaded or bundled one of the same name.
  route('POST', '/api/mibs', ({ body }) => {
    if (!Array.isArray(body?.files)) throw new HttpError(400, 'files must be a list');
    const files = body.files;
    const before = mibLibrary();
    const added = [];
    const errors = [];
    store.tx(() => {
      for (const f of files) {
        const filename = String(f?.filename ?? '').slice(0, 200) || 'MIB';
        if (typeof f?.text !== 'string' || !f.text.trim()) {
          errors.push({ filename, error: 'Empty file' });
          continue;
        }
        let mods;
        try {
          mods = parseMib(f.text);
        } catch (err) {
          errors.push({ filename, error: err.message });
          continue;
        }
        const texts = splitModules(f.text);
        for (const mod of mods) {
          store.putMib({ name: mod.name, filename, text: texts.get(mod.name) ?? f.text });
          added.push({ name: mod.name, filename, replaced: before.modules.get(mod.name)?.source ?? null });
        }
      }
    });
    if (added.length) mibsChanged();
    return { added, errors, modules: mibLibrary().list() };
  });

  route('DELETE', '/api/mibs/:name', ({ params }) => {
    if (!store.deleteMib(params.name)) throw new HttpError(404, 'No uploaded MIB by that name');
    mibsChanged();
    return { modules: mibLibrary().list() };
  });

  route('GET', '/api/monitors/:id/uptime', ({ params, view }) => {
    const m = seeMonitor(params.id, view());
    return store.monitorUptime(m.id, Date.now());
  }, 'view');

  // ---- tags ----------------------------------------------------------------

  const tagOr404 = (id) => {
    const t = store.getTag(Number(id));
    if (!t) throw new HttpError(404, 'Tag not found');
    return t;
  };

  const uniqueTagName = (name, id) => {
    const clash = store.findTagByName(name);
    if (clash && clash.id !== id) throw new HttpError(400, `There is already a tag called "${clash.name}"`);
  };

  route('GET', '/api/tags', () => {
    const counts = new Map();
    for (const ids of store.monitorTagMap().values()) for (const t of ids) counts.set(t, (counts.get(t) ?? 0) + 1);
    return store.listTags().map((t) => ({ ...t, count: counts.get(t.id) ?? 0 }));
  });

  // A tag's uploaded icon arrives as a data URL in `iconData`, as for monitors.
  const tagIconUpload = (body, t, existing) => {
    if (t.icon !== 'upload') return null;
    if (body.iconData) return badRequest(() => decodeDataUrl(body.iconData));
    if (!existing || !store.getTagIcon(existing.id)) throw new HttpError(400, 'Choose an image to upload for the icon');
    return null;
  };

  route('POST', '/api/tags', ({ body }) => {
    const t = normalizeTag(body);
    uniqueTagName(t.name, null);
    const upload = tagIconUpload(body, t, null);
    const id = store.tx(() => {
      const newId = store.createTag(t);
      if (upload) store.setTagIcon(newId, upload);
      return newId;
    });
    engine.touch();
    return store.getTag(id);
  });

  // The order decides which tag's icon a monitor with several gets.
  route('POST', '/api/tags/order', ({ body }) => {
    const ids = idList(body.ids);
    if (!ids) throw new HttpError(400, 'Expected ids: a list of tag ids');
    if (ids.some((id) => !store.getTag(id))) throw new HttpError(400, 'Unknown tag');
    store.tx(() => store.orderTags([...new Set(ids)]));
    engine.touch();
    iconsChanged(null);
    return store.listTags();
  });

  route('PUT', '/api/tags/:id', ({ params, body }) => {
    const existing = tagOr404(params.id);
    const t = normalizeTag(body, existing);
    uniqueTagName(t.name, existing.id);
    const upload = tagIconUpload(body, t, existing);
    store.tx(() => {
      store.updateTag(existing.id, t);
      if (upload) store.setTagIcon(existing.id, upload);
      // Rules written as expressions name their tags; keep them working.
      if (t.name !== existing.name) {
        for (const r of store.listRules()) {
          const expr = r.tagExpr && renameInExpr(r.tagExpr, existing.name, t.name);
          if (expr && expr !== r.tagExpr) store.updateRule(r.id, { ...r, tagExpr: expr });
        }
        for (const p of store.listProblems()) {
          const expr = p.config.tagExpr && renameInExpr(p.config.tagExpr, existing.name, t.name);
          if (expr && expr !== p.config.tagExpr) store.updateProblem(p.id, { ...p, config: { ...p.config, tagExpr: expr } });
        }
        for (const u of store.listUsers()) {
          const expr = u.scope.tagExpr && renameInExpr(u.scope.tagExpr, existing.name, t.name);
          if (expr && expr !== u.scope.tagExpr) store.updateUser(u.id, { scope: { ...u.scope, tagExpr: expr } });
        }
      }
    });
    engine.touch();
    iconsChanged(null);
    return store.getTag(existing.id);
  });

  route('DELETE', '/api/tags/:id', ({ params }) => {
    store.deleteTag(tagOr404(params.id).id);
    engine.touch();
    iconsChanged(null);
    return { ok: true };
  });

  route('GET', '/api/tags/:id/icon', ({ params, view }) => {
    const t = tagOr404(params.id);
    const v = view();
    if (v && !v.tagIds.has(t.id)) throw new HttpError(404, 'Tag not found');
    const icon = store.getTagIcon(t.id);
    if (!icon) throw new HttpError(404, 'No icon');
    return new RawResponse(icon.mime, icon.data, ICON_HEADERS);
  }, 'view');

  // Add (or with remove=true, take off) a tag on several monitors at once,
  // optionally including everything downstream of them.
  route('POST', '/api/tags/:id/apply', ({ params, body }) => {
    const tag = tagOr404(params.id);
    const ids = idList(body.monitorIds) ?? [];
    if (ids.some((id) => !engine.monitors.has(id))) throw new HttpError(400, 'Unknown monitor');
    const targets = new Set(ids);
    if (body.downstream) for (const id of ids) for (const d of engine.graph.descendants(id)) targets.add(d);
    let changed = 0;
    store.tx(() => {
      for (const id of targets) changed += body.remove ? store.untagMonitor(id, tag.id) : store.tagMonitor(id, tag.id);
    });
    if (changed) {
      engine.touch();
      iconsChanged(null);
    }
    return { ok: true, changed, monitors: targets.size };
  });

  // ---- CSV import & export -------------------------------------------------

  const csvFile = (name, text) => new RawResponse('text/csv; charset=utf-8', text, {
    'Content-Disposition': `attachment; filename="${name}"`,
    'Cache-Control': 'no-store',
  });

  route('GET', '/api/csv/export', () => csvFile(`upstream-kuma-monitors-${new Date().toISOString().slice(0, 10)}.csv`, exportCsv(store)));
  route('GET', '/api/csv/template', () => csvFile('upstream-kuma-template.csv', csvTemplate()));
  route('GET', '/api/csv/example', () => csvFile('upstream-kuma-example.csv', CSV_EXAMPLE));
  route('GET', '/api/csv/columns', () => CSV_COLUMNS.map(({ name, types, values, def, required, help }) => ({ name, types, values, def, required, help })));

  // With dryRun nothing is saved; the result says what would happen.
  route('POST', '/api/csv/import', ({ body }) => {
    const mode = ['add', 'update', 'skip'].includes(body.mode) ? body.mode : 'add';
    const res = importCsv(store, String(body.csv ?? ''), { mode, dryRun: Boolean(body.dryRun) });
    if (res.applied) {
      for (const u of res.uploads) icons.saveUpload(u.id, u.img);
      engine.reload(res.affected);
      icons.sync(store.listMonitors(), res.affected);
    }
    const { affected, uploads, ...summary } = res;
    return summary;
  });

  // ---- notifications ------------------------------------------------------

  const normalizeNotification = (body) => {
    const name = String(body.name ?? '').trim();
    if (!name) throw new HttpError(400, 'Name is required');
    if (!providers[body.type]) throw new HttpError(400, `Unknown notification type "${body.type}"`);
    return { name, type: body.type, config: body.config ?? {}, active: body.active !== false };
  };

  route('GET', '/api/notification-types', () => providerCatalog());
  // Web push channels say how many devices signed up to them.
  route('GET', '/api/notifications', () => {
    const devices = store.listPushDevices();
    return store.listNotifications().map((n) => (n.type === 'webpush' ? { ...n, devices: devices.filter((d) => d.channelIds.includes(n.id)).length } : n));
  });

  route('POST', '/api/notifications', ({ body }) => {
    const n = normalizeNotification(body);
    const id = store.tx(() => {
      const newId = store.createNotification(n);
      // "Send it everything": a rule for every problem on every monitor.
      if (body.alertAll) store.createRule({ channelIds: [newId] });
      return newId;
    });
    return store.getNotification(id);
  });

  route('PUT', '/api/notifications/:id', ({ params, body }) => {
    const id = Number(params.id);
    if (!store.getNotification(id)) throw new HttpError(404, 'Notification not found');
    store.updateNotification(id, normalizeNotification(body));
    return store.getNotification(id);
  });

  route('DELETE', '/api/notifications/:id', ({ params }) => {
    store.deleteNotification(Number(params.id));
    return { ok: true };
  });

  route('POST', '/api/notifications/test', async ({ body }) => {
    const n = normalizeNotification({ name: 'Test', ...body });
    // no retries: the form shows what happened straight away
    // a saved Web push channel tests on the devices signed up to it
    const id = n.type === 'webpush' && store.getNotification(Number(body.id))?.type === 'webpush' ? Number(body.id) : 0;
    const [res] = await deliver([{ ...n, id }], {
      kind: 'test',
      title: 'Test: Upstream Kuma is flowing',
      message: [
        'This is a test notification from Upstream Kuma.',
        '',
        'A real alert looks like this:',
        'Alert: Host 2 is unreachable',
        '',
        'Other affected monitors (3):',
        '- Service 2.1',
        '-- Microservice 2.1.1',
        '- Service 2.2',
      ].join('\n'),
      time: Date.now(),
      // an example, for providers that draw the details themselves
      monitor: { id: 0, name: 'Host 2', type: 'ping', target: '192.0.2.2' },
      upstream: ['Internet', 'Core switch'],
      affected: [{ id: 0, name: 'Service 2.1', depth: 1 }, { id: 0, name: 'Microservice 2.1.1', depth: 2 }, { id: 0, name: 'Service 2.2', depth: 1 }],
      facts: [
        { key: 'target', label: 'Target', value: '192.0.2.2' },
        { key: 'reason', label: 'Reason', value: 'No reply (example)' },
        { key: 'time', label: 'Time', value: new Date().toLocaleString() },
      ],
      url: (() => {
        const base = store.getSettings().publicUrl || store.getSetting('oidc')?.publicUrl;
        return base ? `${base.replace(/\/+$/, '')}/#/` : null;
      })(),
    }, { retries: [] });
    if (!res.ok) throw new HttpError(502, res.error);
    return { ok: true };
  });

  // ---- notification rules and problems ---------------------------------------
  // Rules only decide where alerts go, so changing them needs no reload.

  const ruleOr404 = (id) => store.getRule(Number(id)) ?? (() => { throw new HttpError(404, 'Rule not found'); })();

  // Unknown channels and problems are dropped. Tag ids are kept even when the
  // tag is gone: a rule whose tags were all deleted must stop matching rather
  // than quietly widen to every monitor.
  const normalizeRule = (body, base = {}) => {
    const pick = (key, list) => {
      const known = new Set(list.map((x) => x.id));
      return (idList(body[key]) ?? base[key] ?? []).filter((id) => known.has(id));
    };
    let tagExpr = String(body.tagExpr ?? base.tagExpr ?? '').trim();
    if (tagExpr) {
      const expr = parseTagExpr(tagExpr, store.listTags());
      if (expr?.error) throw new HttpError(400, expr.error);
      tagExpr += ')'.repeat(expr?.unclosed ?? 0);
    }
    return {
      channelIds: pick('channelIds', store.listNotifications()),
      problemIds: pick('problemIds', store.listProblems()),
      minSeverity: SEVERITIES[body.minSeverity ?? base.minSeverity] ? (body.minSeverity ?? base.minSeverity) : '',
      tagIds: tagExpr ? [] : (idList(body.tagIds) ?? base.tagIds ?? []),
      tagMatch: (body.tagMatch ?? base.tagMatch) === 'all' ? 'all' : 'any',
      tagExpr,
      downstream: (body.downstream ?? base.downstream) !== false,
    };
  };

  route('GET', '/api/rules', () => store.listRules());

  route('POST', '/api/rules', ({ body }) => store.getRule(store.createRule(normalizeRule(body))));

  route('PUT', '/api/rules/:id', ({ params, body }) => {
    const existing = ruleOr404(params.id);
    store.updateRule(existing.id, normalizeRule(body, existing));
    return store.getRule(existing.id);
  });

  route('DELETE', '/api/rules/:id', ({ params }) => {
    if (!store.deleteRule(Number(params.id))) throw new HttpError(404, 'Rule not found');
    return { ok: true };
  });

  // Value problems come with who they watch: [{ monitorId, state, since, value }]
  // for each watched monitor that has been read, and `waiting` for the rest
  // (SNMP monitors not checked since), `notSnmp` for tagged monitors that
  // can't be read at all.
  const problemsWithCoverage = () => {
    const tags = store.listTags();
    const tagMap = store.monitorTagMap();
    const state = engine.problemState();
    return store.listProblems().map((p) => {
      if (p.kind !== 'value') return p;
      const watched = [];
      const notSnmp = [];
      const tagged = p.config.tagExpr || p.config.tagIds.length;
      for (const m of engine.monitors.values()) {
        if (!m.active || m.type === 'group' || !inScope(p, tagMap.get(m.id) ?? [], tags)) continue;
        if (m.type === 'snmp') watched.push(m.id);
        else if (tagged) notSnmp.push(m.id);
      }
      const known = new Map(state.filter((x) => x.problemId === p.id).map((x) => [x.monitorId, x]));
      return {
        ...p,
        coverage: {
          monitors: watched.filter((id) => known.has(id)).map((id) => known.get(id)),
          waiting: watched.filter((id) => !known.has(id)),
          notSnmp,
        },
      };
    });
  };

  const problemOr404 = (id) => store.getProblem(Number(id)) ?? (() => { throw new HttpError(404, 'Problem definition not found'); })();

  // The SNMP monitors a problem watches, to check straight away after a change.
  const watchedBy = (p) => {
    const tags = store.listTags();
    const tagMap = store.monitorTagMap();
    return store.listMonitors().filter((m) => m.type === 'snmp' && inScope(p, tagMap.get(m.id) ?? [], tags)).map((m) => m.id);
  };

  route('GET', '/api/problems', () => problemsWithCoverage());

  // The value problems watching one monitor, for its page: its state for
  // each, and which reading it answered. state: 'open' | 'ok' | 'unknown'
  // (answers none of the readings) | 'waiting' (not checked since) |
  // 'notSnmp' (tagged, but there is nothing to read).
  route('GET', '/api/monitors/:id/problems', ({ params, view }) => {
    const v = view();
    const m = engine.monitors.get(Number(params.id));
    if (!m || (v && !v.visible.has(m.id))) throw new HttpError(404, 'Monitor not found');
    const tags = store.listTags();
    const mine = store.monitorTagMap().get(m.id) ?? [];
    const state = new Map(engine.problemState().filter((x) => x.monitorId === m.id).map((x) => [x.problemId, x]));
    return store.listProblems()
      .filter((p) => p.kind === 'value' && inScope(p, mine, tags) && (m.type === 'snmp' || p.config.tagExpr || p.config.tagIds.length))
      .map((p) => {
        const x = state.get(p.id);
        return {
          problem: { id: p.id, name: p.name, severity: p.severity, readings: p.config.readings, checks: p.config.checks },
          state: m.type !== 'snmp' ? 'notSnmp' : x?.state ?? 'waiting',
          since: x?.since ?? null,
          value: x?.value ?? '',
          reading: x?.reading ?? null,
        };
      });
  }, 'view');

  route('POST', '/api/problems', ({ body }) => {
    const p = { kind: 'value', ...normalizeValueProblem(body, undefined, store.listTags()) };
    const id = store.createProblem(p);
    engine.reload(watchedBy(p));
    return problemsWithCoverage().find((x) => x.id === id);
  });

  route('PUT', '/api/problems/:id', ({ params, body }) => {
    const existing = problemOr404(params.id);
    if (existing.kind === 'down') {
      const name = String(body.name ?? existing.name).trim();
      if (!name) throw new HttpError(400, 'Name is required');
      const config = { ...existing.config };
      if (body.config?.recovery != null) config.recovery = Boolean(body.config.recovery);
      store.updateProblem(existing.id, { name, severity: 'severe', config });
    } else {
      const next = normalizeValueProblem(body, existing, store.listTags());
      store.updateProblem(existing.id, next);
      // check the monitors it watched and watches now
      engine.reload([...new Set([...watchedBy(existing), ...watchedBy({ ...existing, ...next })])]);
    }
    return problemsWithCoverage().find((x) => x.id === existing.id);
  });

  // Rules that named only this problem would become "any problem" without
  // it, so they go too (the page warns first); others just drop it.
  route('DELETE', '/api/problems/:id', ({ params }) => {
    const existing = problemOr404(params.id);
    if (existing.kind === 'down') throw new HttpError(400, "The built-in problem definition can't be deleted");
    let rulesDeleted = 0;
    store.tx(() => {
      for (const r of store.listRules()) {
        if (!r.problemIds.includes(existing.id)) continue;
        const rest = r.problemIds.filter((id) => id !== existing.id);
        if (rest.length) store.updateRule(r.id, { ...r, problemIds: rest });
        else {
          store.deleteRule(r.id);
          rulesDeleted++;
        }
      }
      store.deleteProblem(existing.id);
    });
    engine.forgetProblem(existing.id);
    return { ok: true, rulesDeleted };
  });

  // ---- alert log & settings -------------------------------------------------

  route('GET', '/api/alerts', ({ query, view }) => {
    const limit = int(query.limit, 100, 1, 1000);
    const v = view();
    if (!v) return store.listAlerts(limit);
    return store.listAlerts(limit * 10).filter((a) => v.visible.has(a.monitorId)).slice(0, limit).map((a) => redactAlert(a, v.visible));
  }, 'view');

  route('GET', '/api/settings', () => store.getSettings());
  route('PUT', '/api/settings', ({ body }) => {
    const old = store.getSettings();
    const publicUrl = String(body.publicUrl ?? old.publicUrl ?? '').trim().replace(/\/+$/, '').slice(0, 500);
    if (publicUrl && !/^https?:\/\/[^\s/]+/.test(publicUrl)) throw new HttpError(400, 'The address must start with https:// (or http://)');
    store.setSettings({ retentionDays: int(body.retentionDays ?? old.retentionDays, 90, 1, 3650), publicUrl });
    return store.getSettings();
  });

  // ---- push monitors (external services call this) -------------------------

  const push = async ({ params, query }) => {
    const res = await engine.receivePush(params.token, { status: query.status, msg: query.msg, ping: query.ping });
    if (!res.found) throw new HttpError(404, 'Unknown push token');
    return res;
  };
  route('GET', '/api/push/:token', push, 'public');
  route('POST', '/api/push/:token', push, 'public');

  // ---- accounts ------------------------------------------------------------

  const ssoConfig = () => oidc.config();
  const ssoProviders = [oidc, google];
  const ssoOn = () => ssoProviders.filter((p) => p.enabled());
  const providerOf = (id) => (id === 'google' ? google : oidc);
  // Password sign-in can be kept for admins only once SSO works, as a way in
  // if the provider is down. (The setting is kept with the generic SSO's.)
  const passwordsFor = (role) => !ssoOn().length || ssoConfig().passwordLogin || role === 'admin';

  const activeAdmins = (except) => store.listUsers().filter((u) => u.role === 'admin' && u.active && u.id !== except).length;
  // Standalone, someone must be able to get into Settings. Under Home
  // Assistant its admins always can, through the sidebar.
  const keepAnAdmin = (id) => {
    if (!auth.addon && !auth.off && !activeAdmins(id)) throw new HttpError(400, 'There must be at least one admin who can sign in');
  };

  const meOf = (who) => ({
    id: who.user.id,
    username: who.user.username,
    name: who.user.name ?? '',
    email: who.user.email ?? '',
    role: who.user.role,
    via: who.via,
    password: Boolean(who.user.passwordHash),
    sso: Boolean(who.user.oidcSub),
    ssoName: who.user.oidcSub ? who.user.oidcName || '' : '',
    google: Boolean(who.user.googleSub),
    googleName: who.user.googleSub ? who.user.googleName || '' : '',
  });

  const normalizeScope = (v, base = {}) => {
    const src = { ...base, ...(v ?? {}) };
    let tagExpr = String(src.tagExpr ?? '').trim();
    if (tagExpr) {
      const expr = parseTagExpr(tagExpr, store.listTags());
      if (expr?.error) throw new HttpError(400, expr.error);
      tagExpr += ')'.repeat(expr?.unclosed ?? 0);
    }
    return {
      all: Boolean(src.all),
      tagIds: tagExpr ? [] : (idList(src.tagIds) ?? []),
      tagMatch: src.tagMatch === 'all' ? 'all' : 'any',
      tagExpr,
    };
  };

  const USERNAME = /^[\p{L}\p{N}._@+-]{1,64}$/u;
  const EMAIL = /^[^\s@]+@[^\s@]+$/;

  const checkPassword = (pw) => {
    if (typeof pw !== 'string' || pw.length < PASSWORD_MIN) throw new HttpError(400, `The password needs at least ${PASSWORD_MIN} characters`);
    if (pw.length > 1024) throw new HttpError(400, 'That password is too long');
  };

  const normalizeUser = (body, base = {}) => {
    const username = String(body.username ?? base.username ?? '').trim();
    if (!USERNAME.test(username)) throw new HttpError(400, 'A username is 1–64 letters, digits and . _ @ + -');
    const clash = store.findUser(username);
    if (clash && clash.id !== base.id) throw new HttpError(400, `There is already a user called "${clash.username}"`);
    const email = String(body.email ?? base.email ?? '').trim().slice(0, 200);
    if (email && !EMAIL.test(email)) throw new HttpError(400, 'That email address doesn\'t look right');
    return {
      username,
      name: String(body.name ?? base.name ?? '').trim().slice(0, 100),
      email,
      role: (body.role ?? base.role) === 'admin' ? 'admin' : 'viewer',
      active: (body.active ?? base.active) !== false,
      scope: normalizeScope(body.scope, base.scope),
    };
  };

  const userOr404 = (id) => store.getUser(Number(id)) ?? (() => { throw new HttpError(404, 'User not found'); })();

  // Who the provider says signed in, for the log and the Users page: its
  // email, else its username (Entra's UPN), else its name.
  const ssoLabel = (claims) => [claims.email, claims.preferred_username, claims.upn, claims.name]
    .find((x) => typeof x === 'string' && x.trim())?.trim().slice(0, 200) ?? '';

  // What the sign-in page says when no usable account goes with an identity,
  // whatever the reason: it never tells whether an account exists, is turned
  // off, or has which address (and the message travels in the URL, so it
  // would end up in proxy logs). The server log has the details.
  const NOT_LINKED = 'No Upstream Kuma account goes with that sign-in. If you have one, sign in another way and link it in Settings → Account, or ask an admin.';

  // An SSO sign-in's account: the one linked to this subject, else the one
  // with its email address (as its email or its username) when the provider
  // vouches for it (Google: Gmail and Workspace addresses only), linked from
  // then on, else a new viewer if accounts are created on first sign-in.
  // Each is logged, with how it was matched.
  const ssoUser = (claims, issuer, provider) => {
    const c = provider.config();
    const sub = `${issuer} ${claims.sub}`;
    const email = typeof claims.email === 'string' ? claims.email.trim().slice(0, 200) : '';
    const trusted = Boolean(email) && provider.emailTrusted(claims);
    const label = ssoLabel(claims);
    const said = `${label || 'someone'} (${c.label}, subject ${claims.sub})`;
    let u = store.findUserBySub(sub, provider.id);
    let how = 'already linked';
    let why = email ? ` or has the email ${email}` : ' and it sent no email';
    if (!u && email && !trusted) why = ` (${email} isn't an address ${c.label} vouches for, so it can't find one: link it from Settings → Account)`;
    if (!u && trusted) {
      const hits = store.findUsersByEmail(email).filter((x) => !x[provider.sub]);
      if (hits.length === 1 && !hits[0].active) {
        log.warn(`SSO sign-in by ${said}: the account with its email, ${hits[0].username}, is turned off`);
        throw new Error(NOT_LINKED);
      }
      if (hits.length === 1) {
        u = hits[0];
        how = 'linked now by email';
        store.updateUser(u.id, { [provider.sub]: sub });
      } else if (hits.length > 1) {
        why = ` (${hits.length} accounts have the email ${email}: link it from Settings → Account)`;
      }
    }
    if (!u) {
      if (!c.autoCreate) {
        log.warn(`SSO sign-in by ${said}: no account is linked to it${why}`);
        throw new Error(NOT_LINKED);
      }
      how = 'new account';
      const want = String(claims.preferred_username || email.split('@')[0] || 'user').replace(/[^\p{L}\p{N}._@+-]/gu, '').slice(0, 60) || 'user';
      let username = want;
      for (let i = 2; store.findUser(username); i++) username = `${want}-${i}`;
      const id = store.createUser({ username, name: String(claims.name ?? '').slice(0, 100), email: trusted && EMAIL.test(email) ? email : '', role: 'viewer', [provider.sub]: sub, scope: {} });
      u = store.getUser(id);
    }
    if (!u.active) {
      log.warn(`SSO sign-in by ${said}: its account ${u.username} is turned off`);
      throw new Error(NOT_LINKED);
    }
    const patch = {};
    if (label !== u[provider.name]) patch[provider.name] = label;
    if (c.adminGroup) {
      const role = groupsOf(claims, c.groupsClaim).includes(c.adminGroup) ? 'admin' : 'viewer';
      if (role !== u.role && (role === 'admin' || auth.addon || activeAdmins(u.id))) patch.role = role;
    }
    if (!u.name && claims.name) patch.name = String(claims.name).slice(0, 100);
    if (!u.email && trusted && EMAIL.test(email)) patch.email = email;
    if (Object.keys(patch).length) {
      store.updateUser(u.id, patch);
      engine.touch();
      u = store.getUser(u.id);
    }
    log.info(`SSO sign-in by ${said} as ${u.username} (${how}${patch.role ? `, now ${patch.role}` : ''})`);
    return u;
  };

  // Linking an identity to the account signed in here (Settings → Account),
  // for addresses that don't find the account by themselves. The callback
  // must come back to the same session that started it.
  const linkUser = (claims, issuer, provider, who, userId) => {
    const c = provider.config();
    if (who?.via !== 'session' || who.user.id !== userId) throw new Error('Sign in again, then link the account');
    const sub = `${issuer} ${claims.sub}`;
    const label = ssoLabel(claims);
    const other = store.findUserBySub(sub, provider.id);
    if (other && other.id !== userId) {
      log.warn(`${who.user.username} tried to link ${label || claims.sub} (${c.label}), which is linked to ${other.username}`);
      throw new Error(`That ${c.label} account is linked to another Upstream Kuma account. An admin can unlink it there.`);
    }
    store.updateUser(userId, { [provider.sub]: sub, [provider.name]: label });
    engine.touch();
    log.info(`${who.user.username} linked ${label || claims.sub} (${c.label}, subject ${claims.sub})`);
  };

  // Where to go after signing in: a hash route of this app, nothing else.
  const safeNext = (v) => (typeof v === 'string' && /^#\/[\w\-./?=&%~]*$/.test(v) ? v : '');
  const toLogin = (message) => `../../../login.html?error=${encodeURIComponent(message)}`;
  const toAccount = (query) => `../../../#/settings/account?${query}`;

  route('GET', '/api/auth/status', ({ who }) => {
    const c = ssoConfig();
    return {
      setup: auth.setupOpen(),
      signedIn: Boolean(who),
      addon: auth.addon,
      sso: oidc.enabled() ? { label: c.label || OIDC_DEFAULTS.label } : null,
      google: google.enabled(),
      password: !ssoOn().length || c.passwordLogin,
    };
  }, 'public');

  route('POST', '/api/auth/login', async ({ req, body }) => {
    const user = await auth.login(req, body.username, body.password);
    if (!passwordsFor(user.role)) throw new HttpError(403, `Sign in with ${ssoOn().map((p) => p.config().label || 'single sign-on').join(' or ')} instead`);
    return json({ ok: true }, { 'Set-Cookie': auth.startSession(user, req) });
  }, 'public');

  // The first account, from the sign-in page of a new install.
  route('POST', '/api/auth/setup', async ({ req, body }) => {
    if (!auth.setupOpen()) throw new HttpError(403, 'Upstream Kuma already has accounts. Sign in instead.');
    const data = normalizeUser({ ...body, role: 'admin', scope: {} });
    checkPassword(body.password);
    const passwordHash = await hashPassword(body.password);
    const id = store.tx(() => {
      if (store.countUsers()) throw new HttpError(403, 'Upstream Kuma already has accounts. Sign in instead.');
      return store.createUser({ ...data, passwordHash });
    });
    return json({ ok: true }, { 'Set-Cookie': auth.startSession(store.getUser(id), req) });
  }, 'public');

  route('POST', '/api/auth/logout', ({ req, who }) => {
    if (who?.tokenHash) store.deleteSession(who.tokenHash);
    return json({ ok: true }, { 'Set-Cookie': clearCookie(SESSION_COOKIE, req) });
  }, 'public');

  // ---- signing in a home-screen app ------------------------------------------
  //
  // An installed web app (iOS especially) shows the provider in a separate
  // browser view, and the sign-in finishes there rather than in the app,
  // possibly with cookies of its own. So the app asks for a handoff, opens
  // the sign-in with its id and waits; the callback marks it signed in, and
  // the app's next claim (with the cookie only it holds) gets the session.
  // When the callback runs without that cookie (another cookie jar), the
  // person confirms in that window first, comparing a code with the app's:
  // otherwise a link to someone else's handoff would sign *them* in as you.
  const handoffs = new Map(); // id -> { secret, code, at, userId, confirm, ready, error }
  const HANDOFF_TTL = 10 * 60000;
  const HANDOFF_COOKIE = 'uk_handoff';
  const CONFIRM_COOKIE = 'uk_handoff_ok';
  const liveHandoff = (id) => {
    const now = Date.now();
    for (const [k, x] of handoffs) if (now - x.at > HANDOFF_TTL) handoffs.delete(k);
    return typeof id === 'string' ? handoffs.get(id) ?? null : null;
  };
  // `<id>.<secret>` from a cookie, if it belongs to a live handoff
  const handoffFrom = (req, name, key) => {
    const [id, secret] = String(parseCookies(req.headers?.cookie)[name] ?? '').split('.');
    const x = liveHandoff(id);
    return x && secret && x[key] && x[key] === sha256(secret) ? { id, x } : null;
  };

  route('POST', '/api/auth/oidc/handoff', ({ req }) => {
    if (!ssoOn().length) throw new HttpError(400, 'Single sign-on is not set up');
    liveHandoff(null);
    if (handoffs.size > 500) handoffs.delete(handoffs.keys().next().value);
    const id = randomToken(16);
    const secret = randomToken(32);
    const code = String(1000 + crypto.randomInt(9000));
    handoffs.set(id, { secret: sha256(secret), code, at: Date.now(), userId: null, confirm: null, ready: false, error: null });
    return json({ id, code }, { 'Set-Cookie': cookie(HANDOFF_COOKIE, `${id}.${secret}`, { req, maxAge: HANDOFF_TTL }) });
  }, 'public');

  // The app asking whether it's signed in yet.
  route('POST', '/api/auth/oidc/handoff/claim', ({ req, who }) => {
    const mine = handoffFrom(req, HANDOFF_COOKIE, 'secret');
    if (who) {
      if (mine) handoffs.delete(mine.id);
      return json({ signedIn: true }, { 'Set-Cookie': clearCookie(HANDOFF_COOKIE, req) });
    }
    if (!mine) return { expired: true };
    const { id, x } = mine;
    if (x.error) {
      handoffs.delete(id);
      return { error: x.error };
    }
    if (!x.ready) return { waiting: true, confirming: Boolean(x.confirm) };
    handoffs.delete(id);
    const user = store.getUser(x.userId);
    if (!user?.active) return { error: 'This account is turned off' };
    return json({ signedIn: true }, { 'Set-Cookie': [auth.startSession(user, req), clearCookie(HANDOFF_COOKIE, req)] });
  }, 'public');

  route('POST', '/api/auth/oidc/handoff/cancel', ({ req }) => {
    const mine = handoffFrom(req, HANDOFF_COOKIE, 'secret');
    if (mine) handoffs.delete(mine.id);
    return json({ ok: true }, { 'Set-Cookie': clearCookie(HANDOFF_COOKIE, req) });
  }, 'public');

  // The sign-in window, when it doesn't share the app's cookies: what to
  // show, then the person's answer.
  route('GET', '/api/auth/oidc/handoff/confirm', ({ req }) => {
    const found = handoffFrom(req, CONFIRM_COOKIE, 'confirm');
    if (!found) throw new HttpError(404, 'This sign-in has expired. Start it again from the app.');
    const u = store.getUser(found.x.userId);
    return { code: found.x.code, name: u?.name || u?.username || '' };
  }, 'public');

  route('POST', '/api/auth/oidc/handoff/confirm', ({ req, body }) => {
    const found = handoffFrom(req, CONFIRM_COOKIE, 'confirm');
    if (!found) throw new HttpError(404, 'This sign-in has expired. Start it again from the app.');
    if (body.cancel) found.x.error = 'The sign-in was cancelled';
    else found.x.ready = true;
    return json({ ok: true }, { 'Set-Cookie': clearCookie(CONFIRM_COOKIE, req) });
  }, 'public');

  // `provider=google` for Google; `link=1` links the identity to the account
  // signed in here instead of signing in.
  route('GET', '/api/auth/oidc/start', async ({ req, query, who }) => {
    const provider = providerOf(query.provider);
    const link = query.link ? (who?.via === 'session' ? who.user.id : -1) : null;
    try {
      if (link === -1) throw new Error('Sign in first, then link the account');
      const handoff = !link && liveHandoff(query.handoff) ? query.handoff : null;
      const { url, state } = await provider.start(req, link ? '' : safeNext(query.next), { handoff, link });
      return redirect(url, { 'Set-Cookie': cookie(STATE_COOKIE, state, { req, maxAge: 600000 }) });
    } catch (err) {
      return redirect(link ? toAccount(`link-error=${encodeURIComponent(err.message)}`) : toLogin(err.message));
    }
  }, 'public');

  route('GET', '/api/auth/oidc/callback', async ({ req, query, who }) => {
    const clear = clearCookie(STATE_COOKIE, req);
    // the provider whose sign-in this is (a stale state fails in either)
    const provider = ssoProviders.find((p) => p.owns(query.state)) ?? oidc;
    let linking = null;
    try {
      const { claims, issuer, next, handoff, link } = await provider.finish({
        code: query.code,
        state: query.state,
        cookieState: parseCookies(req.headers?.cookie)[STATE_COOKIE],
        error: query.error,
        errorDescription: query.error_description,
      }).catch((err) => {
        log.warn(`SSO sign-in (${provider.config().label}) failed: ${err.message}`);
        linking = err.link;
        const x = liveHandoff(err.handoff);
        if (x) x.error = err.message;
        throw err;
      });
      if (link) {
        linking = link;
        linkUser(claims, issuer, provider, who, link);
        return redirect(toAccount(`linked=${provider.id}`), { 'Set-Cookie': clear });
      }
      let user;
      try {
        user = ssoUser(claims, issuer, provider); // logs who it was
      } catch (err) {
        const x = liveHandoff(handoff);
        if (x) x.error = err.message;
        throw err;
      }
      const x = liveHandoff(handoff);
      if (x) {
        x.userId = user.id;
        const mine = handoffFrom(req, HANDOFF_COOKIE, 'secret');
        if (mine?.id === handoff) {
          // the app's own cookies: sign this window in too, the app's claim does the same
          x.ready = true;
          return redirect(`../../../login.html?signed-in=1${next}`, { 'Set-Cookie': [auth.startSession(user, req), clear] });
        }
        const token = randomToken(32);
        x.confirm = sha256(token);
        return redirect('../../../login.html?handoff=confirm', { 'Set-Cookie': [cookie(CONFIRM_COOKIE, `${handoff}.${token}`, { req, maxAge: HANDOFF_TTL }), clear] });
      }
      return redirect(`../../../${next}`, { 'Set-Cookie': [auth.startSession(user, req), clear] });
    } catch (err) {
      return redirect(linking ? toAccount(`link-error=${encodeURIComponent(err.message)}`) : toLogin(err.message), { 'Set-Cookie': clear });
    }
  }, 'public');

  route('GET', '/api/me', ({ who }) => meOf(who), 'view');

  // Unlinking one's own SSO identity, unless it's the only way in.
  route('POST', '/api/me/unlink', ({ who, body }) => {
    if (who.via !== 'session') throw new HttpError(400, 'This account has nothing linked');
    const provider = providerOf(body.provider);
    const other = provider === google ? oidc : google;
    const u = who.user;
    if (!u[provider.sub]) return { ok: true };
    if (!u.passwordHash && !(u[other.sub] && other.enabled())) throw new HttpError(400, 'This is how you sign in, so it stays linked. Ask an admin to set you a password first.');
    store.updateUser(u.id, { [provider.sub]: null, [provider.name]: '' });
    log.info(`${u.username} unlinked ${provider.config().label}`);
    engine.touch();
    return { ok: true };
  }, 'view');

  route('PUT', '/api/me/password', async ({ who, body }) => {
    if (who.via !== 'session' || !who.user.passwordHash) throw new HttpError(400, 'This account has no password to change');
    if (!(await verifyPassword(String(body.current ?? ''), who.user.passwordHash))) throw new HttpError(400, 'The current password is wrong');
    checkPassword(body.password);
    store.updateUser(who.user.id, { passwordHash: await hashPassword(body.password) });
    store.deleteUserSessions(who.user.id, who.tokenHash);
    return { ok: true };
  }, 'view');

  route('GET', '/api/users', () => store.listUsers().map(publicUser));

  // ---- Web push: this account's devices ------------------------------------------
  //
  // Each device signs itself up (Settings → Account), with the push channels it
  // wants. Only accounts signed in here have devices: Home Assistant's
  // stand-in admin has no account to keep them with.

  const pushChannels = () => store.listNotifications().filter((n) => n.type === 'webpush').map((n) => ({ id: n.id, name: n.name, active: n.active }));
  const SERVICE_NAME = [[/apple\.com$/, 'Apple'], [/googleapis\.com$/, 'Google'], [/mozilla\.com$/, 'Mozilla'], [/windows\.com$/, 'Microsoft']];
  const publicDevice = (d) => ({
    id: d.id,
    name: d.name,
    channelIds: d.channelIds,
    createdAt: d.createdAt,
    lastOk: d.lastOk,
    lastError: d.lastError,
    endpoint: d.endpoint, // so a browser can tell which device is itself
    service: SERVICE_NAME.find(([re]) => re.test(new URL(d.endpoint).hostname))?.[1] ?? '',
  });
  const pushAccount = (who) => {
    if (who.via !== 'session') throw new HttpError(400, 'Push notifications go to accounts: open Upstream Kuma at its own address (the home-screen app) and sign in');
    return who.user;
  };
  const pushChannelIds = (v) => {
    const known = new Set(pushChannels().map((c) => c.id));
    return [...new Set(idList(v) ?? [])].filter((id) => known.has(id));
  };
  const myDevice = (who, id) => {
    const d = store.getPushDevice(Number(id));
    if (!d || d.userId !== who.user.id) throw new HttpError(404, 'Device not found');
    return d;
  };

  route('GET', '/api/webpush', ({ who }) => ({
    publicKey: webPush.keys().publicKey,
    channels: pushChannels(),
    devices: who.via === 'session' ? store.listPushDevices(who.user.id).map(publicDevice) : [],
  }), 'view');

  // A device signing up (or again, with a renewed subscription): the same
  // endpoint is the same device, now this account's.
  route('POST', '/api/webpush/devices', ({ who, body }) => {
    const user = pushAccount(who);
    const sub = body.subscription ?? {};
    const endpoint = String(sub.endpoint ?? '');
    if (!pushServiceOk(endpoint)) throw new HttpError(400, 'That isn\'t a push service Upstream Kuma knows (Apple, Google, Mozilla or Microsoft)');
    const p256dh = String(sub.keys?.p256dh ?? '');
    const authKey = String(sub.keys?.auth ?? '');
    if (Buffer.from(p256dh, 'base64url').length !== 65 || Buffer.from(authKey, 'base64url').length < 16) throw new HttpError(400, 'The subscription\'s keys are missing');
    const origin = /^https?:\/\/[^\s/]+$/.test(String(body.origin ?? '')) ? String(body.origin) : '';
    const data = {
      userId: user.id,
      p256dh,
      auth: authKey,
      origin,
      name: String(body.name ?? '').trim().slice(0, 60) || 'Device',
      channelIds: pushChannelIds(body.channelIds),
    };
    const old = store.findPushDevice(endpoint);
    let id;
    if (old) {
      store.updatePushDevice(old.id, data);
      id = old.id;
    } else {
      id = store.createPushDevice({ ...data, endpoint });
    }
    log.info(`${user.username} signed up "${data.name}" for push notifications`);
    return publicDevice(store.getPushDevice(id));
  }, 'view');

  route('PUT', '/api/webpush/devices/:id', ({ who, params, body }) => {
    pushAccount(who);
    const d = myDevice(who, params.id);
    store.updatePushDevice(d.id, {
      name: body.name === undefined ? undefined : String(body.name).trim().slice(0, 60) || d.name,
      channelIds: body.channelIds === undefined ? undefined : pushChannelIds(body.channelIds),
    });
    return publicDevice(store.getPushDevice(d.id));
  }, 'view');

  route('DELETE', '/api/webpush/devices/:id', ({ who, params }) => {
    pushAccount(who);
    store.deletePushDevice(myDevice(who, params.id).id);
    return { ok: true };
  }, 'view');

  // Signing out on a device stops its notifications.
  route('POST', '/api/webpush/forget', ({ who, body }) => {
    const d = who.via === 'session' ? store.findPushDevice(String(body.endpoint ?? '')) : null;
    if (d && d.userId === who.user.id) store.deletePushDevice(d.id);
    return { ok: true };
  }, 'view');

  route('POST', '/api/webpush/devices/:id/test', async ({ who, params }) => {
    pushAccount(who);
    try {
      await webPush.test(myDevice(who, params.id));
    } catch (err) {
      throw new HttpError(502, err.message);
    }
    return { ok: true };
  }, 'view');

  route('POST', '/api/users', async ({ body }) => {
    const data = normalizeUser(body);
    let passwordHash = null;
    if (body.password) {
      checkPassword(body.password);
      passwordHash = await hashPassword(body.password);
    } else if (!ssoOn().length) {
      throw new HttpError(400, 'Give the account a password (single sign-on isn\'t set up)');
    } else if (!data.email && !EMAIL.test(data.username)) {
      throw new HttpError(400, 'An account without a password needs the email address it signs in with');
    }
    const id = store.createUser({ ...data, passwordHash });
    engine.touch();
    return publicUser(store.getUser(id));
  });

  // `password` sets a new one, `removePassword` leaves SSO only, `unlinkSso`
  // and `unlinkGoogle` forget a linked identity (the next sign-in links by
  // email again, where it can).
  route('PUT', '/api/users/:id', async ({ params, body, who }) => {
    const existing = userOr404(params.id);
    const data = normalizeUser(body, existing);
    if (existing.role === 'admin' && existing.active && (data.role !== 'admin' || !data.active)) keepAnAdmin(existing.id);
    const patch = { ...data };
    if (body.password) {
      checkPassword(body.password);
      patch.passwordHash = await hashPassword(body.password);
    } else if (body.removePassword) {
      if (!existing.oidcSub && !existing.googleSub && !(ssoOn().length && (data.email || EMAIL.test(data.username)))) throw new HttpError(400, 'Without a password this account could not sign in');
      patch.passwordHash = null;
    }
    if (body.unlinkSso) Object.assign(patch, { oidcSub: null, oidcName: '' });
    if (body.unlinkGoogle) Object.assign(patch, { googleSub: null, googleName: '' });
    store.updateUser(existing.id, patch);
    // Signed-in sessions end when what they were allowed to do changes.
    if (patch.passwordHash !== undefined || data.role !== existing.role || !data.active) {
      store.deleteUserSessions(existing.id, existing.id === who.user.id ? who.tokenHash : null);
    }
    engine.touch();
    return publicUser(store.getUser(existing.id));
  });

  route('DELETE', '/api/users/:id', ({ params, who }) => {
    const existing = userOr404(params.id);
    if (existing.id === who.user.id) throw new HttpError(400, 'You can\'t delete your own account');
    if (existing.role === 'admin' && existing.active) keepAnAdmin(existing.id);
    store.deleteUser(existing.id);
    engine.touch();
    return { ok: true };
  });

  const ssoView = (req) => {
    const { clientSecret, ...c } = ssoConfig();
    return { ...c, addon: auth.addon, hasSecret: Boolean(clientSecret), redirectUri: c.publicUrl || !auth.addon ? oidc.redirectUri(req) : null, callbackPath: CALLBACK_PATH };
  };

  route('GET', '/api/sso', ({ req }) => ssoView(req));

  // A secret left blank keeps the saved one (the form never sees it);
  // `clearSecret` removes it. Turning SSO on fetches the provider's
  // configuration first, so a typo shows up here, not at sign-in.
  route('PUT', '/api/sso', async ({ req, body }) => {
    const old = ssoConfig();
    const str = (k, max = 500) => String(body[k] ?? old[k] ?? '').trim().slice(0, max);
    const next = {
      enabled: Boolean(body.enabled ?? old.enabled),
      issuer: str('issuer').replace(/\/+$/, ''),
      clientId: str('clientId'),
      clientSecret: body.clearSecret ? '' : (body.clientSecret ? String(body.clientSecret).trim().slice(0, 2000) : old.clientSecret),
      label: str('label', 60) || OIDC_DEFAULTS.label,
      scopes: str('scopes') || OIDC_DEFAULTS.scopes,
      publicUrl: str('publicUrl').replace(/\/+$/, ''),
      autoCreate: Boolean(body.autoCreate ?? old.autoCreate),
      adminGroup: str('adminGroup', 200),
      groupsClaim: str('groupsClaim', 100) || 'groups',
      passwordLogin: (body.passwordLogin ?? old.passwordLogin) !== false,
      selectAccount: Boolean(body.selectAccount ?? old.selectAccount),
    };
    for (const k of ['issuer', 'publicUrl']) {
      if (next[k] && !/^https?:\/\/[^\s/]+/.test(next[k])) throw new HttpError(400, `${k === 'issuer' ? 'The issuer' : 'The public URL'} must start with https:// (or http://)`);
    }
    if (next.enabled) {
      if (!next.issuer || !next.clientId) throw new HttpError(400, 'Single sign-on needs an issuer URL and a client ID');
      if (auth.addon && !next.publicUrl) throw new HttpError(400, 'Under Home Assistant, give the address people open Upstream Kuma at (the public URL), so the provider can send them back to it');
      try {
        const meta = await oidc.discover(next.issuer, { fresh: true });
        if (meta.doc.issuer.replace(/\/+$/, '') !== next.issuer) throw new Error(`The provider calls itself "${meta.doc.issuer}"; use that as the issuer`);
      } catch (err) {
        throw new HttpError(400, err.message);
      }
    }
    store.setSetting('oidc', next);
    return ssoView(req);
  });

  // Whether everyone may still use a password once single sign-on is on
  // (otherwise admins only). Stored with the generic SSO's settings.
  route('PUT', '/api/sso/passwords', ({ body }) => {
    store.setSetting('oidc', { ...store.getSetting('oidc', {}), passwordLogin: body.everyone !== false });
    return { everyone: ssoConfig().passwordLogin };
  });

  // ---- sign in with Google ------------------------------------------------------

  const googleView = (req) => {
    const { enabled, clientId, clientSecret, selectAccount, publicUrl } = google.config();
    return { enabled, clientId, selectAccount, hasSecret: Boolean(clientSecret), addon: auth.addon, publicUrl, redirectUri: publicUrl || !auth.addon ? google.redirectUri(req) : null, callbackPath: CALLBACK_PATH };
  };

  route('GET', '/api/google', ({ req }) => googleView(req));

  // As /api/sso: a blank secret keeps the saved one, `clearSecret` removes it.
  route('PUT', '/api/google', async ({ req, body }) => {
    const old = { ...GOOGLE_DEFAULTS, ...store.getSetting('google', {}) };
    const next = {
      enabled: Boolean(body.enabled ?? old.enabled),
      clientId: String(body.clientId ?? old.clientId ?? '').trim().slice(0, 500),
      clientSecret: body.clearSecret ? '' : (body.clientSecret ? String(body.clientSecret).trim().slice(0, 2000) : old.clientSecret),
      selectAccount: Boolean(body.selectAccount ?? old.selectAccount),
    };
    if (next.clientId && !/\.apps\.googleusercontent\.com$/.test(next.clientId)) throw new HttpError(400, 'A Google client ID ends in .apps.googleusercontent.com');
    if (next.enabled) {
      if (!next.clientId || !next.clientSecret) throw new HttpError(400, 'Sign in with Google needs the client ID and client secret of an OAuth client in Google Cloud');
      if (auth.addon && !google.config().publicUrl) throw new HttpError(400, 'Under Home Assistant, set the public address first (Settings → General), so Google can send people back to it');
      try {
        await google.discover(GOOGLE_ISSUER, { fresh: true });
      } catch (err) {
        throw new HttpError(400, err.message);
      }
    }
    store.setSetting('google', next);
    return googleView(req);
  });

  return async function handle(req, url, body) {
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const match = r.re.exec(url.pathname);
      if (!match) continue;
      const who = auth.identify(req);
      if (r.access !== 'public') {
        if (!who) throw new HttpError(401, auth.setupOpen() ? 'Create the admin account first' : 'Sign in first');
        if (r.access === 'admin' && who.user.role !== 'admin') throw new HttpError(403, 'Only an admin can do that');
      }
      let view;
      const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(match[i + 1])]));
      return r.handler({
        params,
        query: Object.fromEntries(url.searchParams),
        body: body ?? {},
        req,
        who,
        view: () => {
          if (!who) throw new HttpError(401, 'Sign in first');
          if (view === undefined) view = viewFor(who.user);
          return view;
        },
      });
    }
    throw new HttpError(404, 'Not found');
  };
}

// An alert as a viewer sees it: the lists of downstream monitors keep only
// the ones it may see (with the count to match), and channel names are left
// out (they are settings).
export function redactAlert(a, visible) {
  const keep = new Map();
  for (const x of a.affected) {
    if (!visible.has(x.id)) continue;
    const line = `${'-'.repeat(x.depth)} ${x.name}`;
    keep.set(line, (keep.get(line) ?? 0) + 1);
  }
  const out = [];
  const lines = String(a.message ?? '').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const head = /^(.*) \((\d+)\):$/.exec(lines[i]);
    if (!head) {
      out.push(lines[i]);
      continue;
    }
    const list = [];
    while (i + 1 < lines.length && /^-+ /.test(lines[i + 1])) {
      const line = lines[++i];
      if (keep.get(line)) {
        keep.set(line, keep.get(line) - 1);
        list.push(line);
      }
    }
    if (list.length) out.push(`${head[1]} (${list.length}):`, ...list);
    else if (out.at(-1) === '') out.pop();
  }
  return {
    ...a,
    message: out.join('\n'),
    affected: a.affected.filter((x) => visible.has(x.id)),
    delivered: a.delivered.map((d) => (d.pending ? { pending: true, name: 'Sending' } : { ok: d.ok, name: d.ok ? 'Sent' : 'Not delivered' })),
  };
}
