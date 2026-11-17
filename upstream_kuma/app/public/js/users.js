// Settings → Users (admins: accounts, what each viewer sees, single sign-on)
// and Settings → Account (everyone: who you are, your password, sign out).
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
  const [users, sso] = await Promise.all([api('users'), api('sso')]);
  let editing = null; // { id: user id | 'new', draft }
  const listBox = h('div', { class: 'card users-card' });
  const editBox = h('div');
  const ssoBox = h('div');

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
            h('td', { class: 'small' }, [u.password ? 'Password' : null, u.sso ? 'SSO' : u.email && sso.enabled ? 'SSO (not yet)' : null].filter(Boolean).join(' · ') || '—'),
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
        input('email', 'Email', { type: 'email', autocomplete: 'off' }, sso.enabled ? 'Single sign-on finds the account by this address the first time.' : null)),
      h('section', null, h('h3', null, 'Role'), role),
      h('section', null, h('h3', null, 'Sees'), scopeBox,
        d.role === 'viewer' ? h('p', { class: 'help' }, 'Like the tag filter: the monitors with these tags, and everything upstream of them, so a viewer can tell when the cause is further up. Viewers can filter by any tag those monitors carry.') : null),
      h('section', null, h('h3', null, 'Sign-in'),
        h('div', { class: 'field' },
          h('label', { for: 'u-password' }, isNew ? 'Password' : original.password ? 'New password' : 'Password'),
          password,
          h('small', null, sso.enabled ? 'At least 8 characters. Leave it out for single sign-on only.' : 'At least 8 characters.')),
        !isNew && original.password && (original.sso || (sso.enabled && d.email))
          ? h('label', { class: 'check' }, removePw, ' No password: single sign-on only') : null,
        !isNew && original.sso ? h('p', { class: 'small' }, 'Linked to a single sign-on identity. ',
          h('button', {
            type: 'button',
            class: 'linkish',
            onclick: async () => {
              try {
                await api(`users/${original.id}`, { method: 'PUT', body: { unlinkSso: true } });
                toast('Unlinked: the next SSO sign-in links by email again', 'success');
                editing = null;
                await reload();
              } catch (err) {
                toast(err.message, 'error');
              }
            },
          }, 'Unlink')) : null,
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

  paint();
  ssoCard(ssoBox, sso);
  fill(box, h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('h1', null, 'Users'),
      h('p', { class: 'muted' }, 'Admins can do everything. Viewers see the monitors their scope picks by tag, and everything upstream of them, and can\'t change anything.',
        session.me.via === 'ingress' ? ' Home Assistant users are admins here, through the sidebar.' : '')),
    editBox,
    listBox,
    ssoBox));
}

// ---- single sign-on (OpenID Connect) -------------------------------------------------

function ssoCard(box, cfg) {
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
    fill(redirectBox,
      h('span', { class: 'muted small' }, 'Redirect URI to give the provider:'),
      uri ? [h('code', null, uri), h('button', {
        type: 'button',
        class: 'linkish',
        onclick: () => navigator.clipboard?.writeText(uri).then(() => toast('Copied', 'success'), () => toast('Copy it by hand', 'error')),
      }, 'Copy')] : h('span', { class: 'small scope-none' }, 'Fill in the public URL first'));
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
      ssoCard(box, cfg);
    } catch (err) {
      toast(err.message, 'error');
    }
  };
  fill(box, h('form', { class: 'card form sso-card', onsubmit: save },
    h('div', { class: 'card-head' }, h('h2', null, 'Single sign-on'), h('span', { class: `badge ${cfg.enabled ? 'up' : 'paused'}` }, cfg.enabled ? 'On' : 'Off')),
    h('p', { class: 'muted' }, 'Sign in with an OpenID Connect provider (Authentik, Authelia, Keycloak, Google, Microsoft Entra, …). Make a confidential client there with the redirect URI below.'),
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
      check('passwordLogin', 'Allow password sign-in for everyone (otherwise admins only, in case the provider is down)')),
    h('div', { class: 'form-actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save'))));
}

// ---- Settings → Account -----------------------------------------------------------------

export async function renderAccount(box, { state }) {
  const me = session.me;
  const how = { ingress: 'Signed in through Home Assistant.', open: 'Sign-in is turned off (AUTH=off): everyone who can reach Upstream Kuma is an admin.' }[me.via]
    ?? `Signed in with ${me.sso && !me.password ? 'single sign-on' : me.sso ? 'a password or single sign-on' : 'a password'}.`;
  const cards = [h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, me.name || me.username), roleBadge(me.role)),
    me.name ? h('p', { class: 'muted small' }, me.username) : null,
    h('p', null, how),
    me.role === 'viewer' ? h('p', { class: 'muted' }, `You can see ${plural(state.monitors.length, 'monitor')}: the ones picked for you and what they depend on. Ask an admin to change that.`) : null,
    me.via === 'session' ? h('div', { class: 'form-actions' }, h('button', {
      class: 'btn',
      onclick: async () => {
        await api('auth/logout', { method: 'POST' });
        location.replace('login.html');
      },
    }, 'Sign out')) : null)];
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
