// The sign-in page (login.html): sign in with a password or SSO, or on a
// new install create the admin account. Afterwards it goes back to the app,
// to the route it was opened from (the hash travels along).
import { h, svg, fill } from './util.js';
import { sourceLayers } from './flow.js';

const box = document.getElementById('login');
const params = new URLSearchParams(location.search);
const back = () => location.replace(`./${location.hash}`);

// Not api() from util.js: that one comes here on a 401, and a wrong
// password is a 401.
async function call(path, body) {
  const res = await fetch(`api/${path}`, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const field = (id, label, attrs) => h('div', { class: 'field' }, h('label', { for: id }, label), h('input', { id, ...attrs }));
const errorLine = (text) => h('p', { class: 'login-error', role: 'alert' }, text);

function form({ title, intro, fields, submit, onSubmit, quiet = false }) {
  const err = h('div');
  const btn = h('button', { class: `btn${quiet ? '' : ' primary'} login-submit`, type: 'submit' }, submit);
  const el = h('form', {
    class: 'form',
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      fill(err);
      try {
        await onSubmit(Object.fromEntries(fields.map((f) => [f.querySelector('input').id, f.querySelector('input').value])));
      } catch (e2) {
        fill(err, errorLine(e2.message));
        btn.disabled = false;
      }
    },
  }, title ? h('h1', null, title) : null, intro ? h('p', { class: 'muted' }, intro) : null, fields, err, btn);
  return el;
}

// `quiet`: second to the SSO button
function passwordForm(quiet = false) {
  return form({
    quiet,
    fields: [
      field('username', 'Username', { autocomplete: 'username', required: true, autocapitalize: 'none', spellcheck: false, autofocus: true }),
      field('password', 'Password', { type: 'password', autocomplete: 'current-password', required: true }),
    ],
    submit: 'Sign in',
    onSubmit: async (v) => {
      await call('auth/login', v);
      back();
    },
  });
}

// ---- home-screen apps ---------------------------------------------------------
//
// Installed, the app can't follow the provider: iOS shows it in a browser view
// of its own, and the sign-in ends there. So the app opens it in a window and
// waits, asking the server until that sign-in is handed over (api.js).
const STANDALONE = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const HANDOFF_KEY = 'upstream-kuma:handoff';
const saved = () => {
  try {
    const x = JSON.parse(sessionStorage.getItem(HANDOFF_KEY));
    return x && Date.now() - x.at < 10 * 60000 ? x : null;
  } catch {
    return null;
  }
};
const forget = () => {
  try { sessionStorage.removeItem(HANDOFF_KEY); } catch { /* private mode */ }
};

async function startHandoff(startUrl) {
  const { id, code } = await call('auth/oidc/handoff', {});
  try { sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ id, code, at: Date.now() })); } catch { /* private mode */ }
  const url = `${startUrl}&handoff=${encodeURIComponent(id)}`;
  if (!window.open(url, '_blank')) return location.assign(url); // no window: the old way
  waitForHandoff(code);
}

let waiting = null;
function waitForHandoff(code) {
  clearTimeout(waiting?.timer);
  const note = h('p', { class: 'muted' }, 'Finish signing in in the window that opened. You’ll come back here once you’re in.');
  const codeLine = h('p', { class: 'login-handoff-code', hidden: true }, 'If it asks, check it shows ', h('b', null, code), '.');
  const cancel = h('button', { class: 'btn ghost', type: 'button', onclick: async () => {
    stop();
    await call('auth/oidc/handoff/cancel', {}).catch(() => {});
    render();
  } }, 'Cancel');
  fill(box, h('div', { class: 'login-handoff' }, h('h1', null, 'Signing in…'), note, codeLine, cancel));
  const stop = () => {
    clearTimeout(waiting?.timer);
    removeEventListener('focus', ask);
    document.removeEventListener('visibilitychange', ask);
    waiting = null;
    forget();
  };
  const ask = async () => {
    if (!waiting || document.hidden) return;
    clearTimeout(waiting.timer);
    try {
      const r = await call('auth/oidc/handoff/claim', {});
      if (!waiting) return;
      if (r.signedIn) {
        stop();
        return back();
      }
      if (r.expired || r.error) {
        stop();
        return render(r.error || 'The sign-in expired. Try again.');
      }
      codeLine.hidden = !r.confirming;
    } catch { /* not answering: try again */ }
    if (waiting) waiting.timer = setTimeout(ask, 2000);
  };
  waiting = { timer: setTimeout(ask, 2000) };
  addEventListener('focus', ask);
  document.addEventListener('visibilitychange', ask);
}

// In the sign-in window: done, close me (or go on into the app here).
function signedInHere() {
  const here = h('button', { class: 'linkish small', type: 'button', onclick: back }, 'Open Upstream Kuma here instead');
  fill(box, h('div', { class: 'login-handoff' }, h('h1', null, 'You’re signed in'), h('p', { class: 'muted' }, 'Close this window to go back to the app.'), here));
  window.close();
}

// In a sign-in window that doesn't share the app's cookies.
async function confirmHandoff() {
  let info;
  try {
    info = await call('auth/oidc/handoff/confirm');
  } catch (err) {
    return fill(box, h('div', { class: 'login-handoff' }, errorLine(err.message)));
  }
  const answer = async (cancel) => {
    try {
      await call('auth/oidc/handoff/confirm', { cancel });
    } catch (err) {
      return fill(box, h('div', { class: 'login-handoff' }, errorLine(err.message)));
    }
    fill(box, h('div', { class: 'login-handoff' },
      h('h1', null, cancel ? 'Cancelled' : 'Done'),
      h('p', { class: 'muted' }, cancel ? 'Nobody was signed in. You can close this window.' : 'Close this window to go back to the app.')));
    window.close();
  };
  fill(box, h('div', { class: 'login-handoff' },
    h('h1', null, 'Finish signing in to the app?'),
    h('p', null, `You signed in as ${info.name}. The Upstream Kuma app should be showing the code `, h('b', { class: 'login-handoff-num' }, info.code), '.'),
    h('p', { class: 'muted small' }, 'Only continue if you started this sign-in from the app yourself, just now. If you didn’t, someone may be trying to sign in as you: cancel.'),
    h('div', { class: 'login-handoff-actions' },
      h('button', { class: 'btn primary', type: 'button', onclick: () => answer(false) }, 'Continue'),
      h('button', { class: 'btn ghost', type: 'button', onclick: () => answer(true) }, 'Cancel'))));
}

async function render(error = params.get('error')) {
  if (params.get('handoff') === 'confirm') return confirmHandoff();
  if (params.has('signed-in')) return STANDALONE ? back() : signedInHere();
  const resume = STANDALONE && saved();
  if (resume && !waiting) return waitForHandoff(resume.code);
  let status;
  try {
    status = await call('auth/status');
  } catch (err) {
    return fill(box, errorLine(`Upstream Kuma isn't answering: ${err.message}`));
  }
  if (status.signedIn) return back();
  const problem = error ? errorLine(error) : null;

  if (status.setup) {
    return fill(box, form({
      title: 'Welcome',
      intro: 'Create the admin account. It can do everything; add accounts for others later in Settings → Users.',
      fields: [
        field('username', 'Username', { autocomplete: 'username', required: true, autocapitalize: 'none', spellcheck: false, autofocus: true }),
        field('name', 'Your name (optional)', { autocomplete: 'name' }),
        field('password', 'Password', { type: 'password', autocomplete: 'new-password', required: true, minLength: 8 }),
        field('confirm', 'Password again', { type: 'password', autocomplete: 'new-password', required: true, minLength: 8 }),
      ],
      submit: 'Create account',
      onSubmit: async ({ confirm, ...v }) => {
        if (v.password !== confirm) throw new Error('The passwords don’t match');
        await call('auth/setup', v);
        back();
      },
    }));
  }

  const startUrl = `api/auth/oidc/start?next=${encodeURIComponent(location.hash)}`;
  const sso = status.sso
    ? h('a', { class: 'btn primary login-sso', href: startUrl, onclick: STANDALONE ? (e) => {
      e.preventDefault();
      startHandoff(startUrl).catch((err) => render(err.message));
    } : null }, `Sign in with ${status.sso.label}`)
    : null;
  const pw = h('div', { class: 'login-password' });
  if (status.password) fill(pw, sso ? h('div', { class: 'login-or' }, h('span', null, 'or')) : null, passwordForm(Boolean(sso)));
  else {
    // only admins may use a password: kept out of the way
    fill(pw, h('button', { class: 'linkish small login-admin', type: 'button', onclick: () => fill(pw, passwordForm(true)) }, 'Admin sign-in with a password'));
  }
  // no heading: the page and its button say what it's for
  fill(box,
    problem,
    sso,
    pw,
    status.addon ? h('p', { class: 'muted small login-note' }, 'Accounts are made in Home Assistant: open Upstream Kuma from its sidebar, then Settings → Users.') : null);
}

// ---- the node and its streams ----------------------------------------------------

// Every few seconds a stream flows out of the node, drawing itself outward
// as it meanders down and away (behind the card), flows for a while, and
// fades. Drawn like Flows' streams: a bed, moving water, foam. As in the
// Flows, they run between the node's rim and its water, so they come out of
// the water; the node is drawn here, and #login-node only keeps its place.
const STILL = matchMedia('(prefers-reduced-motion: reduce)').matches;
const host = document.getElementById('login-streams');
const node = document.getElementById('login-node');
const layers = sourceLayers();
const rim = svg('g', { class: 'ls-rim' }, layers.rim);
const flowing = svg('g');
const over = svg('g', { class: 'ls-over' }, layers.over);
host.append(rim, flowing, over);
let streamId = 0;

// Where the node's centre is on the page.
// Where the node is drawn, and the streams layer's size, in the layer's own
// units (its pixels). Measured against the layer itself, not the window: on
// a phone the two differ while the browser's bars come and go. Streams start
// from the same point the node is drawn at (sizeStreams() sets both).
const place = { x: 0, y: 0, w: 1, h: 1 };

// A meandering line from (x, y) that leaves the window: it heads off to one
// side and down, wanders, and bends down as it goes, like falling water.
function course(x, y) {
  const w = place.w;
  const hgt = place.h;
  const side = Math.random() < 0.5 ? -1 : 1;
  // out to the side first (clear of the name under the node), then falling
  let a = side > 0 ? -0.05 + Math.random() * 0.4 : Math.PI + 0.05 - Math.random() * 0.4;
  const wobble = 0.25 + Math.random() * 0.35;
  const freq = 0.004 + Math.random() * 0.006;
  const seed = Math.random() * 10;
  const pts = [[x, y]];
  const far = Math.hypot(w, hgt) * 1.2;
  for (let d = 0, step = 26; d < far; d += step) {
    const down = Math.PI / 2;
    a += (down - a) * (d < 120 ? 0.004 : 0.03); // gravity, once clear of the node
    const turn = a + wobble * Math.min(1, d / 200) * Math.sin(seed + d * freq); // calm at the node
    x += Math.cos(turn) * step;
    y += Math.sin(turn) * step;
    pts.push([x, y]);
    if (x < -80 || x > w + 80 || y > hgt + 80) break;
  }
  // Catmull-Rom through the points, as cubic curves
  const p = (i) => pts[Math.max(0, Math.min(pts.length - 1, i))];
  let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const [p0, p1, p2, p3] = [p(i - 1), p(i), p(i + 1), p(i + 2)];
    const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
    const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
    d += `C${c1.map((v) => v.toFixed(1)).join(' ')} ${c2.map((v) => v.toFixed(1)).join(' ')} ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
  }
  return d;
}

function spawn() {
  sizeStreams();
  const d = course(place.x, place.y);
  const id = `ls-${++streamId}`;
  // the mask's stroke uncovers the stream from the node outward
  const reveal = svg('path', { d, pathLength: 1, class: 'ls-reveal' });
  const g = svg('g', { class: 'ls-stream', mask: `url(#${id})` },
    svg('mask', { id, maskUnits: 'userSpaceOnUse', x: 0, y: 0, width: place.w, height: place.h }, reveal),
    svg('path', { d, class: 'ls-bed' }),
    svg('path', { d, class: 'ls-water' }),
    svg('path', { d, class: 'ls-foam' }));
  flowing.append(g);
  const grow = 4200 + Math.random() * 2500;
  reveal.animate([{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: grow, easing: 'cubic-bezier(.3,.1,.4,1)', fill: 'forwards' });
  const fade = g.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 2200, delay: grow + 2500 + Math.random() * 3000, easing: 'ease-in', fill: 'forwards' });
  fade.finished.then(() => g.remove(), () => g.remove());
}

function loop() {
  if (!document.hidden && flowing.childElementCount < 3) spawn();
  setTimeout(loop, 3800 + Math.random() * 3500);
}

function sizeStreams() {
  const box = host.getBoundingClientRect();
  const r = node.getBoundingClientRect();
  if (!box.width || !r.width) return;
  const x = r.left + r.width / 2 - box.left;
  const y = r.top + r.height / 2 - box.top;
  Object.assign(place, { x, y, w: box.width, h: box.height });
  host.setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
  const s = r.width / layers.box;
  const at = `translate(${x - layers.centre[0] * s} ${y - layers.centre[1] * s}) scale(${s})`;
  rim.setAttribute('transform', at);
  over.setAttribute('transform', at);
  host.style.setProperty('--nx', `${x}px`);
  host.style.setProperty('--ny', `${y}px`);
}

// again whenever the card's content (and so where the node sits) changes
sizeStreams();
addEventListener('resize', sizeStreams);
addEventListener('scroll', sizeStreams, { passive: true });
visualViewport?.addEventListener('resize', sizeStreams);
new ResizeObserver(sizeStreams).observe(document.querySelector('.login-wrap'));
if (!STILL) setTimeout(loop, 500);

render();
