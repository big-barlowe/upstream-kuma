// Settings → Users (admins: accounts, what each viewer sees, single sign-on,
// Google) and Settings → Account (everyone: who you are, your password,
// linked sign-ins, sign out).
import { api, h, fill, toast, confirmDialog, fmtAgo, fmtTime, session } from './util.js';
import { tagPill } from './tags.js';
import { tagScope } from './problems.js';
import { scopeTest } from './rules.js';

// What a scope shows, from the monitors the page knows: the ones it picks,
// and those upstream of them. `reachOf` takes the test itself (the scope
// editor hands over the one being typed).
export function reachOf(test, state) {
  const match = state.monitors.filter((m) => test(m.tags));
  const seen = new Set(match.map((m) => m.id));
  const queue = [...seen];
  while (queue.length) {
    for (const p of state.byId.get(queue.pop())?.parents ?? []) {
      if (!seen.has(p)) {
        seen.add(p);
        queue.push(p);
      }
    }
  }
  return { match: match.length, upstream: seen.size - match.length };
}

export const scopeReach = (scope, state) => reachOf(scopeTest(scope, state.tags), state);

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
export const reachText = ({ match, upstream }) => (match
  ? `${plural(match, 'monitor')}${upstream ? `, plus ${upstream} upstream of ${match === 1 ? 'it' : 'them'}` : ''}`
  : 'No monitors');

const roleBadge = (role) => h('span', { class: `badge role-${role}` }, role === 'admin' ? 'Admin' : 'Viewer');

// One line about what a viewer sees.
function scopeSummary(u, state) {
  if (u.role === 'admin') return h('span', { class: 'muted small' }, 'Everything');
  const s = u.scope;
  if (s.all) return h('span', { class: 'muted small' }, 'Every monitor');
  const reach = scopeReach(s, state);
  const what = s.tagExpr
    ? h('code', { class: 'rule-expr' }, s.tagExpr)
    : s.tagIds.length
      ? h('span', { class: 'user-scope-tags' }, s.tagIds.map((id) => state.tagById.get(id)).filter(Boolean).map((t) => tagPill(t)),
        s.tagIds.length > 1 ? h('span', { class: 'muted small' }, s.tagMatch === 'all' ? '(all of them)' : '(any of them)') : null)
      : null;
  return h('span', { class: 'user-scope' }, what, h('span', { class: `small ${reach.match ? 'muted' : 'scope-none'}` }, what ? reachText(reach) : 'Nothing picked yet: sees no monitors'));
}

// ---- Settings → Users --------------------------------------------------------------

export async function renderUsers(box, { state }) {
  const [users, sso, google] = await Promise.all([api('users'), api('sso'), api('google')]);
  let editing = null; // { id: user id | 'new', draft }
  const listBox = h('div', { class: 'card users-card' });
  const editBox = h('div');
  const ssoBox = h('div');
  const googleBox = h('div');
  const passwordsBox = h('div');
  const anySso = () => sso.enabled || google.enabled;
  // Whether a Google sign-in will find this account by its address.
  const gmailish = (u) => /@(gmail|googlemail)\.com$/i.test(u.email || '') || /@(gmail|googlemail)\.com$/i.test(u.username || '');

  const reload = async () => {
    const fresh = await api('users');
    users.splice(0, users.length, ...fresh);
    paint();
  };

  const paint = () => {
    fill(listBox,
      h('div', { class: 'card-head' },
        h('h2', null, 'Accounts'),
        h('button', { class: 'btn small primary', onclick: () => edit(null) }, '+ Add user')),
      users.length
        ? h('div', { class: 'table-scroll' }, h('table', { class: 'users-table' },
          h('thead', null, h('tr', null, ['Name', 'Role', 'Sees', 'Signs in with', 'Last signed in', ''].map((x) => h('th', null, x)))),
          h('tbody', null, users.map((u) => h('tr', { class: `${u.active ? '' : 'user-off'}${editing?.id === u.id ? ' editing' : ''}` },
            h('td', null, h('div', { class: 'user-name' }, u.name || u.username, u.id === session.me.id ? h('span', { class: 'muted small' }, ' (you)') : null),
              u.name ? h('div', { class: 'muted small' }, u.username) : null),
            h('td', null, roleBadge(u.role), u.active ? null : h('span', { class: 'muted small' }, ' turned off')),
            h('td', null, scopeSummary(u, state)),
            h('td', { class: 'small' }, [
              u.password ? 'Password' : null,
              u.sso ? 'SSO' : u.email && sso.enabled ? 'SSO (not yet)' : null,
              u.google ? 'Google' : google.enabled && gmailish(u) ? 'Google (not yet)' : null,
            ].filter(Boolean).join(' · ') || '—',
            // the identities the providers said they were, at the last sign-in
            u.ssoName ? h('div', { class: 'muted user-sso-name', title: 'The single sign-on identity linked to this account' }, u.ssoName) : null,
            u.googleName && u.googleName !== u.ssoName ? h('div', { class: 'muted user-sso-name', title: 'The Google account linked to this account' }, u.googleName) : null),
            h('td', { class: 'small muted nowrap', title: u.lastLogin ? fmtTime(u.lastLogin) : '' }, fmtAgo(u.lastLogin)),
            h('td', { class: 'nowrap' }, h('button', { class: 'btn small', onclick: () => edit(u) }, 'Edit')))))))
        : h('p', { class: 'muted' }, session.me.via === 'ingress'
          ? 'No accounts yet. Home Assistant users get in through the sidebar; add accounts for anyone else, to sign in at the direct port.'
          : 'No accounts yet.'));
    paintEditor();
  };

  const edit = (u) => {
    editing = { id: u ? u.id : 'new', draft: u ? structuredClone(u) : { username: '', name: '', email: '', role: 'viewer', active: true, scope: { all: false, tagIds: [], tagMatch: 'any', tagExpr: '' } } };
    paint();
    editBox.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    editBox.querySelector('input')?.focus();
  };

  const close = () => {
    editing = null;
    paint();
  };

  const paintEditor = () => {
    if (!editing) return fill(editBox);
    const isNew = editing.id === 'new';
    const d = editing.draft;
    const original = isNew ? null : users.find((u) => u.id === editing.id);
    const self = original?.id === session.me.id;
    const input = (key, label, attrs = {}, help) => h('div', { class: 'field' },
      h('label', { for: `u-${key}` }, label),
      h('input', { id: `u-${key}`, value: d[key] ?? '', oninput: (e) => { d[key] = e.target.value; }, ...attrs }),
      help ? h('small', null, help) : null);
    const password = h('input', { id: 'u-password', type: 'password', autocomplete: 'new-password', placeholder: isNew ? '' : 'Leave blank to keep it' });
    const removePw = h('input', { type: 'checkbox', id: 'u-nopw' });
    const scopeBox = h('div', { class: 'user-scope-edit' });
    const paintScope = () => {
      if (d.role === 'admin') return fill(scopeBox, h('p', { class: 'muted small' }, 'Admins see and change everything.'));
      const all = h('label', { class: 'check' },
        h('input', { type: 'checkbox', checked: d.scope.all, onchange: (e) => { d.scope = { ...d.scope, all: e.target.checked }; paintScope(); } }),
        ' Every monitor');
      const tagsBox = h('div');
      fill(scopeBox, all, d.scope.all ? h('p', { class: 'muted small' }, `${plural(state.monitors.length, 'monitor')}, read-only.`) : tagsBox);
      if (!d.scope.all) {
        tagScope(tagsBox, {
          value: d.scope,
          tags: () => state.tags,
          onChange: (v) => {
            d.scope = { ...d.scope, ...v };
            paintScope();
          },
          count: (test) => reachText(reachOf(test, state)),
          none: 'No tags picked: sees no monitors.',
          id: 'u-scope',
        });
      }
    };
    const role = h('div', { class: 'role-pick', role: 'radiogroup', 'aria-label': 'Role' },
      [['viewer', 'Viewer', 'Sees the monitors its scope picks and what is upstream of them. Changes nothing.'], ['admin', 'Admin', 'Sees and changes everything, including settings and accounts.']].map(([value, label, text]) =>
        h('label', { class: `role-opt${d.role === value ? ' on' : ''}` },
          h('input', { type: 'radio', name: 'u-role', value, checked: d.role === value, onchange: () => { d.role = value; paintEditor(); } }),
          h('span', null, h('b', null, label), h('span', { class: 'muted small' }, text)))));

    const save = async (e) => {
      e.preventDefault();
      const body = { username: d.username, name: d.name, email: d.email, role: d.role, active: d.active, scope: d.scope };
      if (password.value) body.password = password.value;
      if (removePw.checked) body.removePassword = true;
      try {
        await api(isNew ? 'users' : `users/${editing.id}`, { method: isNew ? 'POST' : 'PUT', body });
        toast(isNew ? `Added ${d.username}` : 'Saved', 'success');
        editing = null;
        await reload();
      } catch (err) {
        toast(err.message, 'error');
      }
    };

    fill(editBox, h('form', { class: 'card form user-editor', onsubmit: save },
      h('div', { class: 'card-head' }, h('h2', null, isNew ? 'New user' : `Edit ${original.username}`)),
      h('div', { class: 'form-grid' },
        input('username', 'Username', { required: true, autocomplete: 'off', autocapitalize: 'none', spellcheck: false }),
        input('name', 'Name', { autocomplete: 'off' }),
        input('email', 'Email', { type: 'email', autocomplete: 'off' }, sso.enabled || google.enabled
          ? `${sso.enabled ? 'Single sign-on' : 'Google'} finds the account by this address the first time${sso.enabled && google.enabled ? ' (Google only for Gmail and Workspace addresses)' : google.enabled ? ', if it is a Gmail or Workspace address' : ''}.`
          : null)),
      h('section', null, h('h3', null, 'Role'), role),
      h('section', null, h('h3', null, 'Sees'), scopeBox,
        d.role === 'viewer' ? h('p', { class: 'help' }, 'Like the tag filter: the monitors with these tags, and everything upstream of them, so a viewer can tell when the cause is further up. Viewers can filter by any tag those monitors carry.') : null),
      h('section', null, h('h3', null, 'Sign-in'),
        h('div', { class: 'field' },
          h('label', { for: 'u-password' }, isNew ? 'Password' : original.password ? 'New password' : 'Password'),
          password,
          h('small', null, anySso() ? 'At least 8 characters. Leave it out for single sign-on only.' : 'At least 8 characters.')),
        !isNew && original.password && (original.sso || original.google || (anySso() && d.email))
          ? h('label', { class: 'check' }, removePw, ' No password: single sign-on only') : null,
        !isNew && original.sso ? unlinkLine(original, 'unlinkSso',
          original.ssoName ? ['Linked to the single sign-on identity ', h('strong', null, original.ssoName), '. '] : 'Linked to a single sign-on identity (named here after its next sign-in). ',
          'Unlinked: the next SSO sign-in links by email again') : null,
        !isNew && original.google ? unlinkLine(original, 'unlinkGoogle',
          original.googleName ? ['Linked to the Google account ', h('strong', null, original.googleName), '. '] : 'Linked to a Google account (named here after its next sign-in). ',
          'Unlinked from Google') : null,
        h('label', { class: 'check' },
          h('input', { type: 'checkbox', checked: d.active, disabled: self, onchange: (e) => { d.active = e.target.checked; } }),
          ' Can sign in', self ? h('span', { class: 'muted small' }, ' (you)') : null)),
      h('div', { class: 'form-actions' },
        h('button', { class: 'btn primary', type: 'submit' }, isNew ? 'Add user' : 'Save'),
        h('button', { class: 'btn ghost', type: 'button', onclick: close }, 'Cancel'),
        !isNew && !self ? h('button', {
          class: 'btn danger ghost push-right',
          type: 'button',
          onclick: () => confirmDialog(`Delete ${original.username}?`, 'They are signed out and can no longer sign in.', 'Delete', async () => {
            try {
              await api(`users/${original.id}`, { method: 'DELETE' });
              toast(`Deleted ${original.username}`, 'success');
              editing = null;
              await reload();
            } catch (err) {
              toast(err.message, 'error');
              return false;
            }
          }),
        }, 'Delete') : null)));
    paintScope();
  };

  const unlinkLine = (original, key, text, done) => h('p', { class: 'small' }, text,
    h('button', {
      type: 'button',
      class: 'linkish',
      onclick: async () => {
        try {
          await api(`users/${original.id}`, { method: 'PUT', body: { [key]: true } });
          toast(done, 'success');
          editing = null;
          await reload();
        } catch (err) {
          toast(err.message, 'error');
        }
      },
    }, 'Unlink'));

  // once either is on: may everyone still use a password?
  const paintPasswords = () => {
    if (!anySso()) return fill(passwordsBox);
    fill(passwordsBox, h('div', { class: 'card form' },
      h('div', { class: 'card-head' }, h('h2', null, 'Passwords')),
      h('label', { class: 'check' },
        h('input', {
          type: 'checkbox',
          checked: sso.passwordLogin !== false,
          onchange: async (e) => {
            try {
              const r = await api('sso/passwords', { method: 'PUT', body: { everyone: e.target.checked } });
              sso.passwordLogin = r.everyone;
              toast(r.everyone ? 'Everyone may sign in with a password' : 'Only admins may sign in with a password now', 'success');
            } catch (err) {
              e.target.checked = !e.target.checked;
              toast(err.message, 'error');
            }
          },
        }),
        ' Allow password sign-in for everyone (otherwise admins only, in case single sign-on is down)')));
  };
  const saved = () => {
    paint();
    paintPasswords();
  };

  paint();
  ssoCard(ssoBox, sso, saved);
  googleCard(googleBox, google, saved);
  paintPasswords();
  fill(box, h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('h1', null, 'Users'),
      h('p', { class: 'muted' }, 'Admins can do everything. Viewers see the monitors their scope picks by tag, and everything upstream of them, and can\'t change anything.',
        session.me.via === 'ingress' ? ' Home Assistant users are admins here, through the sidebar.' : '')),
    editBox,
    listBox,
    ssoBox,
    googleBox,
    passwordsBox));
}

// The address to give a provider: from the public URL, or this page's own
// address (not under ingress: that is Home Assistant's).
function redirectLine(uri) {
  return [
    h('span', { class: 'muted small' }, 'Redirect URI to give the provider:'),
    uri ? [h('code', null, uri), h('button', {
      type: 'button',
      class: 'linkish',
      onclick: () => navigator.clipboard?.writeText(uri).then(() => toast('Copied', 'success'), () => toast('Copy it by hand', 'error')),
    }, 'Copy')] : h('span', { class: 'small scope-none' }, 'Fill in the public URL first'),
  ];
}

// ---- single sign-on (OpenID Connect) -------------------------------------------------

function ssoCard(box, cfg, onSaved) {
  const d = { ...cfg, clientSecret: '' };
  const text = (key, label, help, attrs = {}) => h('div', { class: 'field' },
    h('label', { for: `sso-${key}` }, label),
    h('input', { id: `sso-${key}`, value: d[key] ?? '', oninput: (e) => { d[key] = e.target.value; if (key === 'publicUrl') paintRedirect(); }, autocomplete: 'off', spellcheck: false, ...attrs }),
    help ? h('small', null, help) : null);
  const check = (key, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d[key], onchange: (e) => { d[key] = e.target.checked; } }), ` ${label}`);
  const redirectBox = h('div', { class: 'sso-redirect' });
  // The address to register with the provider: from the public URL, or this
  // page's own address (not under ingress: that is Home Assistant's).
  const paintRedirect = () => {
    const base = d.publicUrl?.trim() ? d.publicUrl.trim().replace(/\/*$/, '/') : session.me.via === 'ingress' ? null : new URL('./', location.href).href;
    let uri = null;
    try {
      uri = base ? new URL(cfg.callbackPath, base).href : null;
    } catch {
      uri = null;
    }
    fill(redirectBox, redirectLine(uri));
  };
  paintRedirect();
  const save = async (e) => {
    e.preventDefault();
    try {
      const body = { ...d };
      if (!body.clientSecret) delete body.clientSecret;
      const saved = await api('sso', { method: 'PUT', body });
      Object.assign(cfg, saved);
      toast(saved.enabled ? 'Saved: single sign-on is on' : 'Saved', 'success');
      ssoCard(box, cfg, onSaved);
      onSaved();
    } catch (err) {
      toast(err.message, 'error');
    }
  };
  fill(box, h('form', { class: 'card form sso-card', onsubmit: save },
    h('div', { class: 'card-head' }, h('h2', null, 'Single sign-on'), h('span', { class: `badge ${cfg.enabled ? 'up' : 'paused'}` }, cfg.enabled ? 'On' : 'Off')),
    h('p', { class: 'muted' }, 'Sign in with an OpenID Connect provider (Authentik, Authelia, Keycloak, Microsoft Entra, …). Make a confidential client there with the redirect URI below. Google has a card of its own, below.'),
    check('enabled', 'Offer single sign-on on the sign-in page'),
    h('div', { class: 'form-grid' },
      text('issuer', 'Issuer URL', 'Its discovery document is at <issuer>/.well-known/openid-configuration.', { placeholder: 'https://auth.example.com/application/o/upstream-kuma' }),
      text('label', 'Button label', null, { placeholder: 'Single sign-on' }),
      text('clientId', 'Client ID'),
      text('clientSecret', 'Client secret', cfg.hasSecret ? 'Saved. Leave blank to keep it.' : 'Leave blank for a public client (PKCE only).', { type: 'password', placeholder: cfg.hasSecret ? '••••••••' : '' }),
      text('publicUrl', 'Public URL', cfg.addon || session.me.via === 'ingress' ? 'Where people open Upstream Kuma directly (the add-on\'s port or your proxy), e.g. https://uk.example.com. Needed under Home Assistant.' : 'Optional: the address people open Upstream Kuma at, if a proxy hides it.', { placeholder: 'https://uk.example.com' }),
      text('scopes', 'Scopes', null, { placeholder: 'openid profile email' })),
    redirectBox,
    h('section', null, h('h3', null, 'Accounts'),
      h('p', { class: 'muted small' }, 'A sign-in uses the account linked to that identity, or else the one with its email address (linked from then on).'),
      check('autoCreate', 'Create an account on first sign-in (a viewer that sees nothing until you give it a scope)'),
      h('div', { class: 'form-grid' },
        text('adminGroup', 'Admin group', 'Optional. Members of this group are admins, everyone else a viewer, set at every sign-in.', { placeholder: 'upstream-kuma-admins' }),
        text('groupsClaim', 'Groups claim', 'Where the provider lists groups.', { placeholder: 'groups' })),
      check('selectAccount', 'Ask which account every time (the provider shows its account picker instead of signing in whoever is already signed in there)')),
    h('div', { class: 'form-actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save'))));
}

// ---- sign in with Google -------------------------------------------------------------

function googleCard(box, cfg, onSaved) {
  const d = { enabled: cfg.enabled, clientId: cfg.clientId, clientSecret: '', selectAccount: cfg.selectAccount };
  const text = (key, label, help, attrs = {}) => h('div', { class: 'field' },
    h('label', { for: `g-${key}` }, label),
    h('input', { id: `g-${key}`, value: d[key] ?? '', oninput: (e) => { d[key] = e.target.value; }, autocomplete: 'off', spellcheck: false, ...attrs }),
    help ? h('small', null, help) : null);
  const check = (key, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d[key], onchange: (e) => { d[key] = e.target.checked; } }), ` ${label}`);
  const uri = cfg.redirectUri;
  // Google takes http:// only for localhost
  const insecure = uri && /^http:/.test(uri) && !/^http:\/\/(localhost|127\.0\.0\.1)[:/]/.test(uri);
  const save = async (e) => {
    e.preventDefault();
    try {
      const body = { ...d };
      if (!body.clientSecret) delete body.clientSecret;
      const saved = await api('google', { method: 'PUT', body });
      Object.assign(cfg, saved);
      toast(saved.enabled ? 'Saved: Sign in with Google is on' : 'Saved', 'success');
      googleCard(box, cfg, onSaved);
      onSaved();
    } catch (err) {
      toast(err.message, 'error');
    }
  };
  fill(box, h('form', { class: 'card form sso-card', onsubmit: save },
    h('div', { class: 'card-head' }, h('h2', null, 'Sign in with Google'), h('span', { class: `badge ${cfg.enabled ? 'up' : 'paused'}` }, cfg.enabled ? 'On' : 'Off')),
    h('p', { class: 'muted' }, 'In the Google Cloud console, under Google Auth Platform → Clients, create an OAuth client of type “Web application” with the redirect URI below, and copy its client ID and secret here.'),
    check('enabled', 'Offer “Sign in with Google” on the sign-in page'),
    h('div', { class: 'form-grid' },
      text('clientId', 'Client ID', null, { placeholder: '1234567890-abc.apps.googleusercontent.com' }),
      text('clientSecret', 'Client secret', cfg.hasSecret ? 'Saved. Leave blank to keep it.' : null, { type: 'password', placeholder: cfg.hasSecret ? '••••••••' : '' })),
    h('div', { class: 'sso-redirect' }, uri ? redirectLine(uri) : [
      h('span', { class: 'muted small' }, 'Redirect URI to give Google:'),
      h('span', { class: 'small scope-none' }, 'Set the public address in Settings → General first'),
    ]),
    insecure ? h('p', { class: 'small scope-none' }, 'Google only accepts https:// redirect URIs (or http://localhost). Open Upstream Kuma at its https:// address, or set that as the public address in Settings → General.') : null,
    h('section', null, h('h3', null, 'Accounts'),
      h('p', { class: 'muted small' }, 'Nobody gets an account by having a Google account: a Google sign-in uses the account linked to it, or else the one whose email address (or username) is its address, linked from then on. That only goes for Gmail addresses and Google Workspace domains, which Google vouches for. A Google account made with any other address (say you@outlook.com) is linked by its owner, signed in another way, in Settings → Account.'),
      check('selectAccount', 'Show Google’s account picker every time (rather than signing in whoever is signed in to Google there)')),
    h('div', { class: 'form-actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save'))));
}

// ---- linked sign-ins ------------------------------------------------------------------

const STANDALONE = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

// The sign-ins (SSO, Google) that are on, and which of them this account is
// linked to; each can be linked from here, or unlinked if it isn't the only
// way in.
function linkedCard(me, status, rerender) {
  const rows = [
    status.sso ? { id: 'oidc', label: status.sso.label, linked: me.sso, name: me.ssoName } : null,
    status.google ? { id: 'google', label: 'Google', linked: me.google, name: me.googleName } : null,
  ].filter(Boolean);
  if (!rows.length) return null;
  return h('div', { class: 'card' },
    h('h3', null, 'Linked sign-ins'),
    h('p', { class: 'muted small' }, 'Link an account to sign in with it, here or in the app.'),
    h('div', { class: 'linked-list' }, rows.map((r) => h('div', { class: 'linked-row' },
      h('div', null, h('b', null, r.label),
        h('div', { class: 'muted small' }, r.linked ? `Linked${r.name ? `: ${r.name}` : ''}` : 'Not linked')),
      r.linked
        ? h('button', {
          class: 'btn small ghost',
          onclick: async () => {
            try {
              await api('me/unlink', { method: 'POST', body: { provider: r.id } });
              Object.assign(session.me, await api('me'));
              toast(`Unlinked ${r.label}`, 'success');
              rerender();
            } catch (err) {
              toast(err.message, 'error');
            }
          },
        }, 'Unlink')
        : STANDALONE
          ? h('span', { class: 'muted small' }, 'Link it in a browser')
          : h('a', { class: 'btn small', href: `api/auth/oidc/start?provider=${r.id}&link=1` }, `Link ${r.label}`)))));
}

// ---- push notifications on this device ------------------------------------------------
//
// A device signs itself up for the Web push channels it wants (api.js,
// webpush.js); on an iPhone that only works in the app added to the Home
// Screen. The list below it is the account's other devices.

const IOS = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const PUSH_OK = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;

function deviceName() {
  const ua = navigator.userAgent;
  const what = /iPhone/.test(ua) ? 'iPhone' : IOS ? 'iPad' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Device';
  const how = STANDALONE ? 'app' : /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
  return how ? `${what} (${how})` : what;
}

// a VAPID key (base64url) as the bytes subscribe() wants
const keyBytes = (b64) => Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));

export async function pushSubscription() {
  if (!PUSH_OK) return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return reg ? reg.pushManager.getSubscription() : null;
}

function pushCard() {
  const box = h('div', { class: 'card push-card' });
  const paint = async () => {
    let info;
    let sub = null;
    try {
      [info, sub] = await Promise.all([api('webpush'), pushSubscription().catch(() => null)]);
    } catch (err) {
      return fill(box, h('h3', null, 'Push notifications'), h('p', { class: 'muted' }, err.message));
    }
    const names = new Map(info.channels.map((c) => [c.id, c.name]));
    const mine = sub ? info.devices.find((d) => d.endpoint === sub.endpoint) : null;
    const others = info.devices.filter((d) => d !== mine);
    const picked = new Set(mine ? mine.channelIds : info.channels.filter((c) => c.active).map((c) => c.id));
    const run = (fn) => async (e) => {
      const btn = e?.currentTarget;
      if (btn) btn.disabled = true;
      try {
        await fn();
      } catch (err) {
        toast(err.message, 'error');
      }
      if (btn) btn.disabled = false;
    };
    const channelPicks = (onChange) => h('div', { class: 'push-channels' }, info.channels.map((c) => h('label', { class: 'check' },
      h('input', {
        type: 'checkbox',
        checked: picked.has(c.id),
        onchange: (e) => {
          if (e.target.checked) picked.add(c.id);
          else picked.delete(c.id);
          onChange?.();
        },
      }),
      ` ${c.name}`, c.active ? null : h('span', { class: 'muted small' }, ' (turned off)'))));
    const nameInput = h('input', { id: 'push-name', value: mine?.name ?? deviceName(), autocomplete: 'off', maxLength: 60 });

    let here;
    if (!info.channels.length) {
      here = h('p', { class: 'muted' }, session.admin
        ? ['Add a channel of type ', h('b', null, 'Web push'), ' under ', h('a', { href: '#/settings/notifications' }, 'Settings → Notifications'), ', with rules for what it gets. Then turn notifications on here, on each phone.']
        : 'There is no push channel yet. Ask an admin to add one.');
    } else if (!PUSH_OK || !isSecureContext) {
      here = h('p', { class: 'muted' }, IOS && !STANDALONE
        ? 'On an iPhone or iPad, push notifications come to the app on the Home Screen: in Safari, tap Share → Add to Home Screen, open Upstream Kuma from there, and turn them on here.'
        : !isSecureContext ? 'Push notifications need Upstream Kuma at an https:// address.' : 'This browser can’t receive push notifications.');
    } else if (Notification.permission === 'denied') {
      here = h('p', { class: 'muted' }, IOS
        ? 'Notifications are turned off for Upstream Kuma on this device. Turn them on in the iPhone’s Settings → Notifications → Upstream Kuma, then come back.'
        : 'Notifications are blocked for this site. Allow them in the browser’s site settings, then come back.');
    } else if (mine) {
      const save = run(async () => {
        await api(`webpush/devices/${mine.id}`, { method: 'PUT', body: { name: nameInput.value, channelIds: [...picked] } });
        toast('Saved', 'success');
      });
      nameInput.onchange = save;
      here = [
        h('p', null, 'This device gets push notifications from:'),
        channelPicks(save),
        h('div', { class: 'field' }, h('label', { for: 'push-name' }, 'This device’s name'), nameInput),
        mine.lastError ? h('p', { class: 'small scope-none' }, `The last one didn’t arrive: ${mine.lastError}`) : null,
        h('div', { class: 'form-actions' },
          h('button', { class: 'btn', onclick: run(async () => {
            await api(`webpush/devices/${mine.id}/test`, { method: 'POST' });
            toast('Test sent: it should arrive in a moment', 'success');
          }) }, 'Send a test'),
          h('button', { class: 'btn ghost', onclick: run(async () => {
            await api(`webpush/devices/${mine.id}`, { method: 'DELETE' });
            await sub.unsubscribe().catch(() => {});
            toast('Notifications are off on this device', 'success');
            paint();
          }) }, 'Turn off on this device')),
      ];
    } else {
      here = [
        h('p', null, 'Get alerts on this device from:'),
        channelPicks(),
        h('div', { class: 'field' }, h('label', { for: 'push-name' }, 'This device’s name'), nameInput),
        h('div', { class: 'form-actions' },
          h('button', { class: 'btn primary', onclick: run(async () => {
            // asked straight from the tap: iOS allows nothing else
            const answer = await Notification.requestPermission();
            if (answer !== 'granted') {
              paint();
              throw new Error('Notifications weren’t allowed');
            }
            const reg = await navigator.serviceWorker.register('sw.js');
            await navigator.serviceWorker.ready;
            const s2 = await reg.pushManager.getSubscription()
              ?? await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(info.publicKey) });
            await api('webpush/devices', { method: 'POST', body: { subscription: s2.toJSON(), name: nameInput.value, channelIds: [...picked], origin: location.origin } });
            toast('Notifications are on for this device', 'success');
            paint();
          }) }, 'Turn on notifications')),
      ];
    }
    fill(box,
      h('h3', null, 'Push notifications'),
      here,
      others.length ? h('div', { class: 'push-others' },
        h('h4', null, 'Your other devices'),
        h('div', { class: 'linked-list' }, others.map((d) => h('div', { class: 'linked-row' },
          h('div', null, h('b', null, d.name),
            h('div', { class: 'muted small' },
              d.channelIds.map((id) => names.get(id)).filter(Boolean).join(', ') || 'No channels',
              ' · ', d.lastOk ? `last one arrived ${fmtAgo(d.lastOk)}` : 'nothing sent yet'),
            d.lastError ? h('div', { class: 'small scope-none' }, d.lastError) : null),
          h('button', { class: 'btn small ghost', onclick: run(async () => {
            await api(`webpush/devices/${d.id}`, { method: 'DELETE' });
            toast(`Removed ${d.name}`, 'success');
            paint();
          }) }, 'Remove'))))) : null);
  };
  paint();
  return box;
}

// ---- Settings → Account -----------------------------------------------------------------

export async function renderAccount(box, { state }) {
  // back from linking (api.js redirects here with the outcome)
  const back = new URLSearchParams(location.hash.split('?')[1] ?? '');
  if (back.has('linked') || back.has('link-error')) {
    history.replaceState(null, '', '#/settings/account');
    if (back.has('linked')) toast(`Linked your ${back.get('linked') === 'google' ? 'Google' : 'single sign-on'} account`, 'success');
    else toast(back.get('link-error'), 'error');
  }
  const me = session.me;
  const status = me.via === 'session' ? await api('auth/status').catch(() => ({})) : {};
  const how = { ingress: 'Signed in through Home Assistant.', open: 'Sign-in is turned off (AUTH=off): everyone who can reach Upstream Kuma is an admin.' }[me.via]
    ?? `Signs in with ${[me.password ? 'a password' : null, me.sso ? status.sso?.label || 'single sign-on' : null, me.google ? 'Google' : null].filter(Boolean).join(' or ') || 'nothing yet'}.`;
  const cards = [h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, me.name || me.username), roleBadge(me.role)),
    me.name ? h('p', { class: 'muted small' }, me.username) : null,
    h('p', null, how),
    me.role === 'viewer' ? h('p', { class: 'muted' }, `You can see ${plural(state.monitors.length, 'monitor')}: the ones picked for you and what they depend on. Ask an admin to change that.`) : null,
    me.via === 'session' ? h('div', { class: 'form-actions' }, h('button', {
      class: 'btn',
      onclick: async () => {
        // this device's notifications were this account's: they stop
        const sub = await pushSubscription().catch(() => null);
        if (sub) {
          await api('webpush/forget', { method: 'POST', body: { endpoint: sub.endpoint } }).catch(() => {});
          await sub.unsubscribe().catch(() => {});
        }
        await api('auth/logout', { method: 'POST' });
        location.replace('login.html');
      },
    }, 'Sign out')) : null)];
  if (me.via === 'session') cards.push(pushCard(), linkedCard(me, status, () => renderAccount(box, { state })));
  if (me.via === 'session' && me.password) {
    const cur = h('input', { id: 'a-cur', type: 'password', autocomplete: 'current-password', required: true });
    const next = h('input', { id: 'a-new', type: 'password', autocomplete: 'new-password', required: true, minLength: 8 });
    const again = h('input', { id: 'a-again', type: 'password', autocomplete: 'new-password', required: true, minLength: 8 });
    cards.push(h('form', {
      class: 'card form',
      onsubmit: async (e) => {
        e.preventDefault();
        if (next.value !== again.value) return toast('The new passwords don’t match', 'error');
        try {
          await api('me/password', { method: 'PUT', body: { current: cur.value, password: next.value } });
          for (const i of [cur, next, again]) i.value = '';
          toast('Password changed. Other devices are signed out.', 'success');
        } catch (err) {
          toast(err.message, 'error');
        }
      },
    },
    h('h3', null, 'Change password'),
    h('div', { class: 'field' }, h('label', { for: 'a-cur' }, 'Current password'), cur),
    h('div', { class: 'field' }, h('label', { for: 'a-new' }, 'New password'), next, h('small', null, 'At least 8 characters.')),
    h('div', { class: 'field' }, h('label', { for: 'a-again' }, 'New password again'), again),
    h('div', { class: 'form-actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Change password'))));
  }
  fill(box, h('div', { class: 'stack' }, h('div', { class: 'page-head' }, h('h1', null, 'Account')), cards));
}
