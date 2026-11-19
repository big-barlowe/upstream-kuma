import os from 'node:os';
import { haRequest } from './checkers/homeassistant.js';
import { isAddon, log } from './config.js';

// An alert passed to every provider:
//   { kind: 'down' | 'up' | 'problem' | 'resolved' | 'test', title, message,
//     monitor, affected, time, problem?: { id, name, severity },
//     facts, upstream, url, reminder? }
// `title` is the one-line subject ("Alert: Host 2 is unreachable"); `message`
// is the plain-text body including the tree of affected downstream monitors.
// For providers that lay an alert out themselves: `facts` are its details
// ([{ key, label, value }]: target, reason, value, duration, time),
// `affected` the downstream tree ({ id, name, depth }, in order), `upstream`
// the names above the monitor (root first), `url` a link to it or null.

// How loud an alert should be: 'urgent' (a monitor down, a severe problem),
// 'warning', or 'calm' (resolved, info, test).
export function level(a) {
  if (a.kind === 'down') return 'urgent';
  if (a.kind === 'problem') return a.problem?.severity === 'severe' ? 'urgent' : a.problem?.severity === 'warning' ? 'warning' : 'calm';
  return 'calm';
}

// "Back up" and "resolved" alerts, which can sound different from the rest.
export const isRecovery = (a) => a.kind === 'up' || a.kind === 'resolved';
// The channel's sound for this alert ('' = the app's default).
const soundFor = (cfg, a) => String((isRecovery(a) ? cfg.resolvedSound : cfg.alertSound) ?? '').trim();

// Pushover's built-in sounds (an account's uploaded ones work by name too).
const PUSHOVER_SOUNDS = [
  ['pushover', 'Pushover (default)'], ['bike', 'Bike'], ['bugle', 'Bugle'], ['cashregister', 'Cash Register'],
  ['classical', 'Classical'], ['cosmic', 'Cosmic'], ['falling', 'Falling'], ['gamelan', 'Gamelan'],
  ['incoming', 'Incoming'], ['intermission', 'Intermission'], ['magic', 'Magic'], ['mechanical', 'Mechanical'],
  ['pianobar', 'Piano Bar'], ['siren', 'Siren'], ['spacealarm', 'Space Alarm'], ['tugboat', 'Tug Boat'],
  ['alien', 'Alien Alarm (long)'], ['climb', 'Climb (long)'], ['persistent', 'Persistent (long)'],
  ['echo', 'Pushover Echo (long)'], ['updown', 'Up Down (long)'], ['vibrate', 'Vibrate only'], ['none', 'None (silent)'],
].map(([value, label]) => ({ value, label }));
const pushoverSound = (key, label, help) => ({ key, label, suggest: PUSHOVER_SOUNDS, help });

// Home Assistant Companion app: on Android a notification's sound is its
// channel's, set in Android's settings, so alerts and recoveries go to
// channels of their own.
export const HA_CHANNELS = { alert: 'Upstream Kuma alerts', resolved: 'Upstream Kuma resolved' };
const HA_IOS_SOUNDS = ['default', 'none'].map((value) => ({ value, label: value === 'none' ? 'None (silent)' : 'The default tone' }));
const haSound = (key, label, help) => ({ key, label, placeholder: 'default', suggest: HA_IOS_SOUNDS, help });

// The `data` for a Companion app notification: the logo, where a tap goes,
// the colour, sounds. Only for notify services, and only when it's a phone
// (mobile_app_…) or a sound option is set: other notify services may refuse
// keys they don't know. `link`: the monitor's page, else Home Assistant's
// panel for the add-on.
export function haPushData(cfg, a, service, link = a.url ?? haPanel()) {
  if (!service.startsWith('mobile_app_') && !cfg.alertSound && !cfg.resolvedSound && !cfg.critical) return null;
  const sound = soundFor(cfg, a);
  const critical = Boolean(cfg.critical) && level(a) === 'urgent';
  const { kind } = headline(a);
  const data = {
    subtitle: `Upstream Kuma · ${kind}`, // iOS, under the title, as on the Chat card
    channel: HA_CHANNELS[isRecovery(a) ? 'resolved' : 'alert'],
    color: chatLook(a).color, // Android
    icon_url: LOGO, // Android
    attachment: { url: LOGO, 'content-type': 'png' }, // iOS: the logo beside the text
    group: `upstream-kuma-${a.monitor?.id ?? 'test'}`, // Android: a monitor's alerts together
  };
  if (link) {
    Object.assign(data, {
      url: link, // iOS
      clickAction: link, // Android
      actions: [{ action: 'URI', title: 'Open in Upstream Kuma', uri: link }],
    });
  }
  if (level(a) === 'urgent') Object.assign(data, { ttl: 0, priority: 'high' }); // ring now, not when the phone next syncs
  if (critical) {
    data.channel = 'alarm_stream'; // Android: the alarm volume, through Do Not Disturb
    data.push = { sound: { name: sound || 'default', critical: 1, volume: 1.0 } };
  } else if (sound) {
    data.push = { sound };
  }
  return data;
}

// A notification's push payload is at most 4 KB on an iPhone, title, data
// and all: the text gets about half.
const HA_BYTES = 2000;
const NTFY_BYTES = 3800; // ntfy's limit is 4,096
const PUSHOVER_CHARS = 1024;
const bytes = (max) => (t) => Buffer.byteLength(t) <= max;

const POST_TIMEOUT = 20000;

// The Web push sender (a WebPush from webpush.js), set by createApi(): it
// needs the store and who may see what.
let pushSender = null;
export const setPushSender = (sender) => {
  pushSender = sender;
};

// An error not worth retrying: the service answered and said no (a 4xx
// other than 408/429), or the channel is missing a setting.
const permanent = (message) => Object.assign(new Error(message), { permanent: true });

async function post(url, body, headers = {}) {
  const host = (() => {
    try {
      return new URL(url).host;
    } catch {
      throw permanent(`Not a URL: ${url}`);
    }
  })();
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: typeof body === 'string' ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(POST_TIMEOUT),
    });
  } catch (err) {
    // say what went wrong, not "fetch failed" / "The operation was aborted"
    if (err.name === 'TimeoutError' || err.name === 'AbortError') throw new Error(`No answer from ${host} within ${POST_TIMEOUT / 1000}s`);
    const cause = err.cause;
    throw new Error(`Couldn't reach ${host}: ${cause?.code ? `${cause.code}${cause.hostname ? ` (${cause.hostname})` : ''}` : cause?.message || err.message}`);
  }
  // always read the answer, so the connection is free for the next alert
  const text = await res.text().catch(() => '');
  if (!res.ok) {
    const message = `HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ''}`;
    throw res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429 ? permanent(message) : new Error(message);
  }
}

// ---- Google Chat ---------------------------------------------------------------
// Google Chat takes only its own message format, so a generic webhook pointed
// at it sends that too. An alert is a card: the status, its details, and the
// flow it sits in (the monitors above it, it, and what it cut off, drawn as an
// indented tree in Flows' colours), with a link to the monitor when
// Upstream Kuma knows its address.
const isGoogleChat = (url) => {
  try {
    return new URL(url).hostname === 'chat.googleapis.com';
  } catch {
    return false;
  }
};

// Read on Chat's light and dark themes alike.
const CHAT = { down: '#ef4444', up: '#14b8a6', pending: '#f59e0b', blocked: '#64748b', info: '#0ea5e9', line: '#94a3b8' };
const CHAT_LOGO = 'https://raw.githubusercontent.com/big-barlowe/upstream-kuma/main/upstream_kuma/icon.png';
const FACT_ICON = { target: 'dns', reason: 'info', value: 'monitoring', duration: 'timer', time: 'schedule' };
const CHAT_ROWS = 40; // downstream rows shown before "and N more"
const INDENT = '\u2003\u2002'; // em + en space: not collapsed like ordinary spaces

const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const font = (color, s) => `<font color="${color}">${s}</font>`;

// What the card says about the monitor: status word, its colour, an icon,
// the colour of the downstream monitors listed, and what that list is.
function chatLook(a) {
  const n = a.affected?.length ?? 0;
  switch (a.kind) {
    case 'down': return { word: a.reminder ? 'STILL DOWN' : 'DOWN', color: CHAT.down, icon: 'error', below: CHAT.blocked, list: `${n} downstream cut off` };
    case 'up': return { word: 'UP', color: CHAT.up, icon: 'check_circle', below: CHAT.pending, list: `${n} downstream re-checking` };
    case 'problem': {
      const sev = a.problem?.severity;
      const color = sev === 'severe' ? CHAT.down : sev === 'warning' ? CHAT.pending : CHAT.info;
      return { word: (a.problem?.name ?? 'Problem').toUpperCase(), color, icon: 'warning', below: CHAT.line, list: `${n} downstream` };
    }
    case 'resolved': return { word: 'RESOLVED', color: CHAT.up, icon: 'check_circle', below: CHAT.line, list: `${n} downstream` };
    default: return { word: 'TEST', color: CHAT.info, icon: 'notifications', below: CHAT.blocked, list: `${n} downstream (example)` };
  }
}

// The flow, as rows: up to three monitors above (root side first), the
// monitor, then its downstream tree, the first `limit` of it. Each row is
// { level, kind: 'above' | 'up' | 'self' | 'down' | 'more', name?, n? }.
function flowRows(a, limit = CHAT_ROWS) {
  const up = a.upstream ?? [];
  const shown = up.slice(-3);
  const rows = [];
  if (up.length > shown.length) rows.push({ level: 0, kind: 'above', n: up.length - shown.length });
  const first = rows.length;
  shown.forEach((name, i) => rows.push({ level: first + i, kind: 'up', name }));
  const at = rows.length;
  rows.push({ level: at, kind: 'self', name: a.monitor?.name ?? 'Monitor' });
  const affected = a.affected ?? [];
  for (const x of affected.slice(0, limit)) rows.push({ level: at + x.depth, kind: 'down', name: x.name });
  if (affected.length > limit) rows.push({ level: at + 1, kind: 'more', n: affected.length - limit });
  return rows;
}

// The flow as lines of Chat's HTML, in Flows' colours.
function chatFlow(a, look) {
  return flowRows(a).map((r) => {
    const text = {
      above: () => font(CHAT.line, `… ${r.n} more above`),
      up: () => `${font(CHAT.up, '●')} ${font(CHAT.line, esc(r.name))}`,
      self: () => `${font(look.color, '●')} <b>${esc(r.name)}</b> ${font(look.color, `<b>${esc(look.word)}</b>`)}`,
      down: () => `${font(look.below, '●')} ${esc(r.name)}`,
      more: () => font(CHAT.line, `… and ${r.n} more`),
    }[r.kind]();
    return (r.level ? `${INDENT.repeat(r.level - 1)}${font(CHAT.line, '└')} ` : '') + text;
  });
}

// ---- The card, for phones ------------------------------------------------------
// Pushover, ntfy and the Home Assistant Companion app show what the Google
// Chat card shows, as text: the status, the details, and the flow, with
// coloured dots (emoji, or Pushover's <font> tags), the logo where the
// service can show one, and a tap that opens the monitor.

export const LOGO = CHAT_LOGO;
const DOT = { [CHAT.down]: '🔴', [CHAT.up]: '🟢', [CHAT.pending]: '🟠', [CHAT.blocked]: '⚪', [CHAT.info]: '🔵', [CHAT.line]: '⚪' };

// The header's two parts: "Alert: Router is unreachable" → { kind: 'Alert',
// headline: 'Router is unreachable' }.
export function headline(a) {
  const prefix = /^([^:]{1,20}):\s*/.exec(a.title ?? '');
  return { kind: prefix ? prefix[1] : 'Alert', headline: prefix ? a.title.slice(prefix[0].length) : a.title };
}

// The card's body as text. `html`: Pushover's tags (<b>, <font color>);
// otherwise emoji dots. `fits(text)` says whether it's short enough: the
// downstream tree is cut ("… and N more") until it is.
export function cardText(a, { html = false, fits = () => true } = {}) {
  const look = chatLook(a);
  const n = a.affected?.length ?? 0;
  const e = html ? esc : (x) => String(x ?? '');
  const paint = (color, x) => (html ? font(color, x) : x);
  const bold = (x) => (html ? `<b>${x}</b>` : x);
  const dot = (color) => (html ? font(color, '●') : DOT[color] ?? '⚪');
  const status = `${html ? font(look.color, `<b>● ${e(look.word)}</b>`) : `${dot(look.color)} ${look.word}`}${n ? paint(CHAT.line, ` · ${look.list}`) : ''}`;
  const facts = (a.facts ?? []).map((f) => `${bold(e(f.label))}: ${e(f.value)}`);
  const line = (r) => {
    const text = {
      above: () => paint(CHAT.line, `… ${r.n} more above`),
      up: () => `${dot(CHAT.up)} ${paint(CHAT.line, e(r.name))}`,
      self: () => `${dot(look.color)} ${bold(e(r.name))} ${html ? font(look.color, `<b>${e(look.word)}</b>`) : `· ${look.word}`}`,
      down: () => `${dot(look.below)} ${e(r.name)}`,
      more: () => paint(CHAT.line, `… and ${r.n} more`),
    }[r.kind]();
    return (r.level ? `${INDENT.repeat(r.level - 1)}${paint(CHAT.line, '└')} ` : '') + text;
  };
  const build = (limit) => [status, ...facts, '', bold('Flow'), ...flowRows(a, limit).map(line)].join('\n');
  let limit = Math.min(n, CHAT_ROWS);
  let text = build(limit);
  while (!fits(text) && limit > 0) text = build(--limit);
  return text;
}

// Home Assistant's own panel for the add-on, for a tap when Upstream Kuma
// has no public address: the Supervisor names the container after the
// add-on's slug ("a1b2c3d4-upstream-kuma" for "a1b2c3d4_upstream_kuma").
function haPanel() {
  const m = isAddon && /^([a-z0-9]+)-upstream-kuma$/.exec(os.hostname());
  return m ? `/hassio/ingress/${m[1]}_upstream_kuma` : null;
}

// The plain version: a bold title over the message in a code block (at most
// 4,096 characters).
function googleChatText(a) {
  const head = `*${a.title}*\n`;
  let body = a.message;
  const room = 4096 - head.length - 8;
  if (body.length > room) body = `${body.slice(0, room - 2)}\n…`;
  return { text: `${head}\`\`\`${body}\`\`\`` };
}

// A card, or if Chat refuses it, the plain version, so an alert still gets
// there (a test shows the refusal instead).
async function sendGoogleChat(url, a) {
  try {
    await post(url, googleChatMessage(a));
  } catch (err) {
    if (a.kind === 'test' || !/^HTTP 400/.test(err.message)) throw err;
    log.warn(`Google Chat refused the alert card (${err.message}); sent it as text`);
    await post(url, googleChatText(a));
  }
}

function googleChatMessage(a) {
  const look = chatLook(a);
  const n = a.affected?.length ?? 0;
  const prefix = /^([^:]{1,20}):\s*/.exec(a.title);
  const headline = prefix ? a.title.slice(prefix[0].length) : a.title;
  const facts = (a.facts ?? []).map((f) => ({
    decoratedText: {
      topLabel: f.label,
      text: esc(f.value),
      wrapText: true,
      startIcon: { materialIcon: { name: FACT_ICON[f.key] ?? 'info' } },
    },
  }));
  const status = {
    decoratedText: {
      topLabel: 'Status',
      text: `${font(look.color, `<b>● ${esc(look.word)}</b>`)}${n ? font(CHAT.line, ` · ${look.list}`) : ''}`,
      wrapText: true,
      startIcon: { materialIcon: { name: look.icon } },
    },
  };
  const lines = chatFlow(a, look);
  // a long tree folds: the first lines stay, the rest open on a click
  const KEEP = 14;
  const flow = lines.length > KEEP + 4
    ? { header: 'Flow', collapsible: true, uncollapsibleWidgetsCount: 1, widgets: [{ textParagraph: { text: lines.slice(0, KEEP).join('<br>') } }, { textParagraph: { text: lines.slice(KEEP).join('<br>') } }] }
    : { header: 'Flow', widgets: [{ textParagraph: { text: lines.join('<br>') } }] };
  const sections = [{ widgets: [status, ...facts] }, flow];
  if (a.url) {
    sections.push({
      widgets: [{
        buttonList: {
          buttons: [{
            text: 'Open in Upstream Kuma',
            icon: { materialIcon: { name: 'open_in_new' } },
            color: { red: 0.05, green: 0.55, blue: 0.75, alpha: 1 },
            onClick: { openLink: { url: a.url } },
          }],
        },
      }],
    });
  }
  return {
    fallbackText: `${a.title}${n ? ` (${look.list})` : ''}`,
    cardsV2: [{
      cardId: `uk-${a.kind}`,
      card: {
        header: {
          title: headline,
          subtitle: `Upstream Kuma · ${prefix ? prefix[1] : 'Alert'}`,
          imageUrl: CHAT_LOGO,
          imageType: 'CIRCLE',
          imageAltText: 'Upstream Kuma',
        },
        sections,
      },
    }],
  };
}

function required(cfg, ...keys) {
  for (const k of keys) if (!cfg[k]) throw permanent(`Missing "${k}"`);
}

export const providers = {
  homeassistant: {
    label: 'Home Assistant',
    fields: [
      { key: 'service', label: 'Service', placeholder: 'notify.mobile_app_my_phone', help: 'Any notify.* service, or persistent_notification.create' },
      haSound('alertSound', 'Alert sound (iPhone, optional)', 'The full file name of a sound in the Companion app: an iOS sound such as Tink.caf (import the system sounds first, in the app’s notification sound settings), one of its own .wav sounds, or one you added. Blank = the default tone.'),
      haSound('resolvedSound', 'Resolved sound (iPhone, optional)', 'For “back up” and resolved alerts. Blank = the default tone.'),
      { key: 'critical', label: 'Critical alerts: down alerts (and severe problems) sound at full volume even when the phone is muted or in a Focus', type: 'checkbox' },
    ],
    help: `On a phone with the Home Assistant Companion app (notify.mobile_app_…), an alert shows what a Google Chat card does: the status, the details and the flow, with the Upstream Kuma logo. Tapping it opens the monitor in Upstream Kuma when it has a public address (Settings → General), otherwise its panel in Home Assistant. Sounds: on an iPhone, name them below. On Android, a notification’s sound is its channel’s: alerts arrive on the channel “${HA_CHANNELS.alert}” and recoveries on “${HA_CHANNELS.resolved}”. Once one of each has arrived, set their sounds in Android’s notification settings for the Companion app.`,
    async send(cfg, a) {
      required(cfg, 'service');
      const [domain, service] = cfg.service.replace(/^\//, '').split('.');
      if (!domain || !service) throw permanent('Service must look like domain.service');
      const data = domain === 'notify' ? haPushData(cfg, a, service) : null;
      const body = domain === 'persistent_notification'
        ? { title: a.title, message: a.message, notification_id: `upstream_kuma_${a.monitor?.id ?? 'test'}` }
        // a phone shows the card's header: the headline, with "Upstream Kuma · Alert" under it
        : { title: data ? headline(a).headline : a.title, message: cardText(a, { fits: bytes(HA_BYTES) }), ...(data ? { data } : {}) };
      await haRequest(`/api/services/${domain}/${service}`, { method: 'POST', body });
    },
  },

  ntfy: {
    label: 'ntfy',
    fields: [
      { key: 'server', label: 'Server URL', placeholder: 'https://ntfy.sh' },
      { key: 'topic', label: 'Topic' },
      { key: 'token', label: 'Access token (optional)', secret: true },
      { key: 'priority', label: 'Priority for down alerts (1-5)', placeholder: '5' },
      { key: 'resolvedPriority', label: 'Priority for resolved alerts (1-5)', placeholder: '3', help: 'A priority of its own gives recoveries a sound of their own (see above). 1 and 2 are silent.' },
    ],
    help: 'Alerts show what a Google Chat card does, with the Upstream Kuma logo (Android), and open the monitor when Upstream Kuma has a public address (Settings → General). ntfy messages can’t carry a sound: the phone plays the one set for the message’s priority. In the ntfy Android app, set a sound per priority (Settings → Channel settings), or per topic (the topic’s ⋮ → Subscription settings → Custom notification settings). Down alerts use the priority below, warnings 4, other alerts 3.',
    async send(cfg, a) {
      required(cfg, 'topic');
      const server = (cfg.server || 'https://ntfy.sh').replace(/\/$/, '');
      const priority = (v, def) => Math.min(5, Math.max(1, Math.round(Number(v)) || def));
      await post(server, {
        topic: cfg.topic,
        title: a.title,
        message: cardText(a, { fits: bytes(NTFY_BYTES) }),
        priority: isRecovery(a) ? priority(cfg.resolvedPriority, 3) : { urgent: priority(cfg.priority, 5), warning: 4, calm: 3 }[level(a)],
        tags: [isRecovery(a) ? 'white_check_mark' : { urgent: 'rotating_light', warning: 'warning', calm: 'droplet' }[level(a)]],
        icon: LOGO,
        ...(a.url ? { click: a.url, actions: [{ action: 'view', label: 'Open in Upstream Kuma', url: a.url, clear: true }] } : {}),
      }, cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {});
    },
  },

  discord: {
    label: 'Discord',
    fields: [{ key: 'webhookUrl', label: 'Webhook URL', secret: true }],
    async send(cfg, a) {
      required(cfg, 'webhookUrl');
      await post(cfg.webhookUrl, {
        username: 'Upstream Kuma',
        embeds: [{
          title: a.title,
          description: '```\n' + a.message.slice(0, 3900) + '\n```',
          color: { urgent: 0xef4444, warning: 0xfbbf24, calm: 0x22d3ee }[level(a)],
          timestamp: new Date(a.time).toISOString(),
        }],
      });
    },
  },

  slack: {
    label: 'Slack',
    fields: [{ key: 'webhookUrl', label: 'Incoming webhook URL', secret: true }],
    async send(cfg, a) {
      required(cfg, 'webhookUrl');
      await post(cfg.webhookUrl, { text: `*${a.title}*\n\`\`\`${a.message}\`\`\`` });
    },
  },

  googlechat: {
    label: 'Google Chat',
    fields: [{ key: 'webhookUrl', label: 'Webhook URL', secret: true, help: 'In the space: Apps & integrations → Webhooks → Add webhook, then copy its URL' }],
    async send(cfg, a) {
      required(cfg, 'webhookUrl');
      await sendGoogleChat(cfg.webhookUrl, a);
    },
  },

  telegram: {
    label: 'Telegram',
    fields: [
      { key: 'botToken', label: 'Bot token', secret: true },
      { key: 'chatId', label: 'Chat ID' },
    ],
    async send(cfg, a) {
      required(cfg, 'botToken', 'chatId');
      await post(`https://api.telegram.org/bot${cfg.botToken}/sendMessage`, {
        chat_id: cfg.chatId,
        text: `${a.title}\n\n${a.message}`,
      });
    },
  },

  pushover: {
    label: 'Pushover',
    help: `Alerts show what a Google Chat card does (with colours once opened in the app), with a link to the monitor when Upstream Kuma has a public address (Settings → General). Pushover shows your application’s icon: for the Upstream Kuma logo, upload ${LOGO} as its icon at pushover.net.`,
    fields: [
      { key: 'userKey', label: 'User key', secret: true },
      { key: 'appToken', label: 'Application token', secret: true },
      pushoverSound('alertSound', 'Alert sound (optional)', 'One of Pushover’s sounds, or the name of one you uploaded at pushover.net. Blank = your default tone in the Pushover app.'),
      pushoverSound('resolvedSound', 'Resolved sound (optional)', 'For “back up” and resolved alerts. Blank = your default tone.'),
    ],
    async send(cfg, a) {
      required(cfg, 'userKey', 'appToken');
      const sound = soundFor(cfg, a);
      await post('https://api.pushover.net/1/messages.json', {
        token: cfg.appToken,
        user: cfg.userKey,
        title: a.title,
        // formatted in the app; the notification itself shows it as plain text
        message: cardText(a, { html: true, fits: (t) => [...t].length <= PUSHOVER_CHARS }),
        html: 1,
        priority: level(a) === 'urgent' ? 1 : 0,
        timestamp: Math.floor((a.time ?? Date.now()) / 1000),
        ...(a.url ? { url: a.url, url_title: 'Open in Upstream Kuma' } : {}),
        ...(sound ? { sound } : {}),
      });
    },
  },

  gotify: {
    label: 'Gotify',
    fields: [
      { key: 'server', label: 'Server URL', placeholder: 'https://gotify.example.com' },
      { key: 'appToken', label: 'Application token', secret: true },
    ],
    async send(cfg, a) {
      required(cfg, 'server', 'appToken');
      await post(`${cfg.server.replace(/\/$/, '')}/message`, {
        title: a.title,
        message: a.message,
        priority: { urgent: 8, warning: 6, calm: 4 }[level(a)],
      }, { 'X-Gotify-Key': cfg.appToken });
    },
  },

  webhook: {
    label: 'Webhook (JSON)',
    fields: [{ key: 'url', label: 'URL' }],
    async send(cfg, a) {
      required(cfg, 'url');
      if (isGoogleChat(cfg.url)) return sendGoogleChat(cfg.url, a);
      await post(cfg.url, {
        kind: a.kind,
        title: a.title,
        message: a.message,
        time: new Date(a.time).toISOString(),
        monitor: a.monitor,
        problem: a.problem ?? null,
        affected: a.affected,
        upstream: a.upstream ?? [],
        facts: a.facts ?? [],
        url: a.url ?? null,
      });
    },
  },

  // Phones and browsers that signed up to this channel (webpush.js); they
  // sign up themselves, in Settings → Account.
  webpush: {
    label: 'Web push (phones, browsers)',
    fields: [],
    help: 'Phones and browsers sign up to this channel themselves: in Settings → Account, on each one (on an iPhone, in the app added to the Home Screen). Rules decide which alerts it gets; a viewer\'s devices only get those about monitors the viewer can see.',
    async send(cfg, a, ch) {
      if (!pushSender) throw permanent('Web push is not set up');
      await pushSender.sendChannel(ch, a);
    },
  },

  email: {
    label: 'Email (SMTP)',
    fields: [
      { key: 'host', label: 'SMTP host' },
      { key: 'port', label: 'Port', placeholder: '587' },
      { key: 'secure', label: 'Use TLS from the start (port 465)', type: 'checkbox' },
      { key: 'username', label: 'Username' },
      { key: 'password', label: 'Password', secret: true },
      { key: 'from', label: 'From', placeholder: 'Upstream Kuma <alerts@example.com>' },
      { key: 'to', label: 'To (comma separated)' },
    ],
    async send(cfg, a) {
      required(cfg, 'host', 'from', 'to');
      const { default: nodemailer } = await import('nodemailer');
      const transport = nodemailer.createTransport({
        host: cfg.host,
        port: Number(cfg.port || 587),
        secure: Boolean(cfg.secure),
        auth: cfg.username ? { user: cfg.username, pass: cfg.password } : undefined,
      });
      await transport.sendMail({ from: cfg.from, to: cfg.to, subject: a.title, text: a.message });
    },
  },
};

// Sends to every channel; never throws. Returns a delivery report per channel.
// A failed send is tried again after these waits (a timeout, a dropped
// connection, a 5xx or 429), unless the service refused it outright.
export const RETRY_DELAYS = [5000, 30000, 120000];
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Sends the alert to each channel: [{ id, name, ok, error?, tries }].
// `retries`: the waits between tries ([] for Send test, which reports at once).
export async function deliver(channels, alert, { retries = RETRY_DELAYS, sleep = wait } = {}) {
  return Promise.all(channels.map(async (ch) => {
    const provider = providers[ch.type];
    for (let tries = 1; ; tries++) {
      try {
        if (!provider) throw permanent(`Unknown notification type "${ch.type}"`);
        await provider.send(ch.config, alert, ch);
        log.info(`Sent "${alert.title}" via ${ch.name}${tries > 1 ? ` (try ${tries})` : ''}`);
        return { id: ch.id, name: ch.name, ok: true, tries };
      } catch (err) {
        const again = !err.permanent && tries <= retries.length;
        if (again) {
          log.warn(`Notification "${ch.name}" failed (try ${tries}): ${err.message}; trying again in ${retries[tries - 1] / 1000}s`);
          await sleep(retries[tries - 1]);
          continue;
        }
        log.error(`Notification "${ch.name}" failed:`, err.message);
        return { id: ch.id, name: ch.name, ok: false, error: tries > 1 ? `${err.message} (tried ${tries} times)` : err.message, tries };
      }
    }
  }));
}

export function providerCatalog() {
  return Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, { label: p.label, fields: p.fields, help: p.help }]));
}
