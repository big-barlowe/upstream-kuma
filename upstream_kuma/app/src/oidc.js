// Single sign-on with OpenID Connect: the authorization code flow with PKCE.
// The ID token is checked against the provider's keys (JWKS), issuer,
// audience, expiry and nonce. No dependency: node:crypto verifies RS*, PS*,
// ES*, EdDSA and HS* (keyed with the client secret) signatures.
import crypto from 'node:crypto';
import { HttpError } from './validate.js';
import { randomToken } from './auth.js';

export const OIDC_DEFAULTS = {
  enabled: false,
  issuer: '',
  clientId: '',
  clientSecret: '',
  label: 'Single sign-on',
  scopes: 'openid profile email',
  publicUrl: '',
  autoCreate: false,
  adminGroup: '',
  groupsClaim: 'groups',
  passwordLogin: true,
  selectAccount: false,
};

// Sign in with Google: an OpenID provider with a fixed issuer, no groups,
// and no accounts made on first sign-in (anyone has a Google account).
export const GOOGLE_ISSUER = 'https://accounts.google.com';
export const GOOGLE_DEFAULTS = {
  enabled: false,
  clientId: '',
  clientSecret: '',
  selectAccount: true,
};
// Google is the authority for these addresses: Gmail, and a Workspace
// domain (the ID token's `hd`). A Google account can also be made with any
// other address, which Google checked once but doesn't own, so that one
// never finds an account by itself (Google's advice too).
const GMAIL = /@(gmail|googlemail)\.com$/i;
export const googleOwnsEmail = (claims) => {
  const email = typeof claims.email === 'string' ? claims.email.trim() : '';
  if (claims.email_verified !== true && claims.email_verified !== 'true') return false;
  if (GMAIL.test(email)) return true;
  const hd = typeof claims.hd === 'string' ? claims.hd.toLowerCase() : '';
  return Boolean(hd) && email.toLowerCase().endsWith(`@${hd}`);
};

export const CALLBACK_PATH = 'api/auth/oidc/callback';
export const STATE_COOKIE = 'uk_oidc';
const PENDING_TTL = 10 * 60000;
const DISCOVERY_TTL = 3600000;
const TIMEOUT = 10000;

const b64json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

const VERIFY = {
  RS256: ['sha256'], RS384: ['sha384'], RS512: ['sha512'],
  PS256: ['sha256', 'pss'], PS384: ['sha384', 'pss'], PS512: ['sha512', 'pss'],
  ES256: ['sha256', 'ec'], ES384: ['sha384', 'ec'], ES512: ['sha512', 'ec'],
  EdDSA: [null],
};

// Check a JWS signature. `keys` is the provider's JWKS key list; HS* use the
// client secret.
export function verifyJwt(token, { keys, secret }) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('The ID token is not a JWT');
  const header = b64json(parts[0]);
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], 'base64url');
  const alg = header.alg;
  let ok;
  if (/^HS(256|384|512)$/.test(alg)) {
    if (!secret) throw new Error(`The ID token is signed with ${alg}, which needs a client secret`);
    const mac = crypto.createHmac(`sha${alg.slice(2)}`, secret).update(data).digest();
    ok = mac.length === sig.length && crypto.timingSafeEqual(mac, sig);
  } else if (VERIFY[alg]) {
    const [hash, kind] = VERIFY[alg];
    const candidates = keys.filter((k) => (!header.kid || k.kid === header.kid) && (!k.use || k.use === 'sig') && (!k.alg || k.alg === alg));
    if (!candidates.length) throw new Error('None of the provider\'s keys matches the ID token');
    ok = candidates.some((jwk) => {
      try {
        const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        const opts = kind === 'pss' ? { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
          : kind === 'ec' ? { key, dsaEncoding: 'ieee-p1363' } : key;
        return crypto.verify(hash, data, opts, sig);
      } catch {
        return false;
      }
    });
  } else {
    throw new Error(`Unsupported ID token algorithm "${alg}"`);
  }
  if (!ok) throw new Error('The ID token\'s signature is not valid');
  return { header, claims: b64json(parts[1]) };
}

// `issuer` may be a list: Google's tokens say either of two.
export function checkClaims(claims, { issuer, clientId, nonce, now = Date.now() }) {
  const skew = 120;
  const t = now / 1000;
  const issuers = [issuer].flat();
  if (!issuers.includes(claims.iss)) throw new Error(`The ID token is from "${claims.iss}", not "${issuers[0]}"`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) throw new Error('The ID token is for a different client');
  if (aud.length > 1 && claims.azp && claims.azp !== clientId) throw new Error('The ID token is for a different client');
  if (typeof claims.exp !== 'number' || claims.exp + skew < t) throw new Error('The ID token has expired');
  if (typeof claims.nbf === 'number' && claims.nbf - skew > t) throw new Error('The ID token is not valid yet');
  if (claims.nonce !== nonce) throw new Error('The sign-in did not match its request (nonce)');
  if (!claims.sub) throw new Error('The ID token has no subject');
}

export const groupsOf = (claims, name) => {
  const v = claims?.[name || 'groups'];
  return Array.isArray(v) ? v.map(String) : typeof v === 'string' ? v.split(/[,\s]+/).filter(Boolean) : [];
};

// One provider: `id` 'oidc' (any OpenID provider, settings key `oidc`) or
// 'google' (settings key `google`). Each account links one identity of each,
// in `oidcSub`/`oidcName` and `googleSub`/`googleName`.
export class Oidc {
  // `fetch` is injectable for tests.
  constructor({ store, fetch = globalThis.fetch, now = Date.now, id = 'oidc' }) {
    this.store = store;
    this.fetch = fetch;
    this.now = now;
    this.id = id;
    this.sub = `${id}Sub`;
    this.name = `${id}Name`;
    this.pending = new Map(); // state -> { nonce, verifier, redirectUri, next, handoff, link, at }
    this.meta = null; // { issuer, at, doc, jwks }
  }

  // Google's settings are filled out to look like a provider's: the generic
  // one's public URL (else Settings → General's) makes its redirect URI too.
  config() {
    const generic = { ...OIDC_DEFAULTS, ...this.store.getSetting('oidc', {}) };
    if (this.id !== 'google') return generic;
    return {
      ...OIDC_DEFAULTS,
      ...GOOGLE_DEFAULTS,
      ...this.store.getSetting('google', {}),
      issuer: GOOGLE_ISSUER,
      label: 'Google',
      scopes: 'openid email profile',
      publicUrl: generic.publicUrl || this.store.getSettings().publicUrl || '',
      autoCreate: false,
      adminGroup: '',
    };
  }

  enabled() {
    const c = this.config();
    return c.enabled && Boolean(c.issuer && c.clientId);
  }

  // Whether the provider's word on this email address is enough to find the
  // account with it.
  emailTrusted(claims) {
    if (this.id === 'google') return googleOwnsEmail(claims);
    return claims.email_verified !== false && claims.email_verified !== 'false';
  }

  // Whether this sign-in (by its state) was started here.
  owns(state) {
    return typeof state === 'string' && this.pending.has(state);
  }

  async #json(url, init = {}) {
    let res;
    try {
      res = await this.fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT), headers: { Accept: 'application/json', ...init.headers } });
    } catch (err) {
      throw new Error(`Couldn't reach ${new URL(url).host}: ${err.cause?.message ?? err.message}`);
    }
    const text = await res.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`${new URL(url).host} answered ${res.status} with something that isn't JSON`);
    }
    if (!res.ok) throw new Error(body.error_description || body.error || `${new URL(url).host} answered ${res.status}`);
    return body;
  }

  // The provider's metadata, cached for an hour (and refetched when the
  // issuer changes or a key is missing).
  async discover(issuer, { fresh = false } = {}) {
    const iss = issuer.replace(/\/+$/, '');
    if (!fresh && this.meta?.issuer === iss && this.now() - this.meta.at < DISCOVERY_TTL) return this.meta;
    const doc = await this.#json(`${iss}/.well-known/openid-configuration`);
    for (const k of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
      if (!doc[k]) throw new Error(`The provider's configuration has no ${k}`);
    }
    const jwks = await this.#json(doc.jwks_uri);
    this.meta = { issuer: iss, at: this.now(), doc, keys: Array.isArray(jwks.keys) ? jwks.keys : [] };
    return this.meta;
  }

  // Where the provider sends the browser back: the public URL if set,
  // otherwise this request's own origin (through any proxy).
  redirectUri(req) {
    const c = this.config();
    if (c.publicUrl) return new URL(CALLBACK_PATH, c.publicUrl.replace(/\/*$/, '/')).href;
    const hdr = req.headers ?? {};
    const first = (v) => String(v ?? '').split(',')[0].trim();
    const proto = first(hdr['x-forwarded-proto']) || (req.socket?.encrypted ? 'https' : 'http');
    const host = first(hdr['x-forwarded-host']) || hdr.host || 'localhost';
    const prefix = first(hdr['x-forwarded-prefix']).replace(/\/+$/, '');
    return `${proto}://${host}${prefix}/${CALLBACK_PATH}`;
  }

  // Begin a sign-in: the URL to send the browser to, and the state that
  // ties the callback to this browser (set as a cookie).
  // `link`: the signed-in account to link the identity to, instead of
  // signing in.
  async start(req, next, { handoff = null, link = null } = {}) {
    const c = this.config();
    if (!this.enabled()) throw new HttpError(400, `${this.id === 'google' ? 'Sign in with Google' : 'Single sign-on'} is not set up`);
    const { doc } = await this.discover(c.issuer);
    const state = randomToken(24);
    const nonce = randomToken(24);
    const verifier = randomToken(48);
    const redirectUri = this.redirectUri(req);
    const now = this.now();
    for (const [k, p] of this.pending) if (now - p.at > PENDING_TTL) this.pending.delete(k);
    if (this.pending.size > 1000) this.pending.delete(this.pending.keys().next().value);
    this.pending.set(state, { nonce, verifier, redirectUri, next, handoff, link, at: now });
    const url = new URL(doc.authorization_endpoint);
    const scopes = new Set(['openid', ...String(c.scopes || OIDC_DEFAULTS.scopes).split(/\s+/).filter(Boolean)]);
    for (const [k, v] of Object.entries({
      response_type: 'code',
      client_id: c.clientId,
      redirect_uri: redirectUri,
      scope: [...scopes].join(' '),
      state,
      nonce,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    })) url.searchParams.set(k, v);
    // the provider's account picker every time, rather than signing in
    // whoever it already has a session for
    if (c.selectAccount) url.searchParams.set('prompt', 'select_account');
    return { url: url.href, state };
  }

  // Finish it: trade the code for tokens and return the verified claims
  // (merged with userinfo) and where to go next.
  // A failure carries `handoff`, so a home-screen app waiting on it can say
  // so, and `link`, so a link goes back to the account page.
  async finish(args) {
    const p = args.state ? this.pending.get(args.state) : null;
    return this.#finish(args, p).catch((err) => {
      err.handoff = p?.handoff ?? null;
      err.link = p?.link ?? null;
      throw err;
    });
  }

  async #finish({ code, state, cookieState, error, errorDescription }, p) {
    if (p) this.pending.delete(state);
    if (error) throw new Error(errorDescription || error);
    if (!p || this.now() - p.at > PENDING_TTL) throw new Error('The sign-in expired or was started elsewhere. Try again.');
    if (!cookieState || cookieState !== state) throw new Error('The sign-in was started in a different browser. Try again.');
    if (!code) throw new Error('The provider sent no authorization code');
    const c = this.config();
    let meta = await this.discover(c.issuer);
    const { doc } = meta;
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: p.redirectUri, code_verifier: p.verifier });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const methods = doc.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
    if (c.clientSecret && methods.includes('client_secret_basic')) {
      headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.clientSecret)}`).toString('base64')}`;
    } else {
      form.set('client_id', c.clientId);
      if (c.clientSecret) form.set('client_secret', c.clientSecret);
    }
    const tokens = await this.#json(doc.token_endpoint, { method: 'POST', headers, body: form.toString() });
    if (!tokens.id_token) throw new Error('The provider sent no ID token');
    let verified;
    try {
      verified = verifyJwt(tokens.id_token, { keys: meta.keys, secret: c.clientSecret });
    } catch (err) {
      // keys may have rotated
      if (!/keys matches/.test(err.message)) throw err;
      meta = await this.discover(c.issuer, { fresh: true });
      verified = verifyJwt(tokens.id_token, { keys: meta.keys, secret: c.clientSecret });
    }
    const claims = verified.claims;
    const issuers = this.id === 'google' ? [doc.issuer, 'accounts.google.com'] : doc.issuer;
    checkClaims(claims, { issuer: issuers, clientId: c.clientId, nonce: p.nonce, now: this.now() });
    let info = {};
    if (doc.userinfo_endpoint && tokens.access_token) {
      try {
        info = await this.#json(doc.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        if (info.sub !== claims.sub) info = {};
      } catch {
        info = {}; // the ID token's claims will do
      }
    }
    return { claims: { ...info, ...claims, [c.groupsClaim || 'groups']: claims[c.groupsClaim || 'groups'] ?? info[c.groupsClaim || 'groups'] }, issuer: doc.issuer, next: p.next, handoff: p.handoff, link: p.link };
  }
}
