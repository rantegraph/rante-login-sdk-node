/*! Rante Login SDK for Node.js 1.0.0 - "Sign in with Rante" on your server. MIT License. */
// Built on jose (https://github.com/panva/jose) for every JWT and key operation.
//
// Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with:
// - the authorization code flow with PKCE (S256), state and nonce, and the iss response parameter (RFC 9207);
// - client authentication by private_key_jwt (RFC 7523, a Signed JWT key linked to the app) for server-side
//   websites, or none (PKCE alone) for browser-only websites;
// - RS256 ID tokens, a pairwise sub, and a userinfo endpoint.

import { KeyObject, createHash, createPrivateKey, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { SignJWT, createRemoteJWKSet, customFetch, errors as joseErrors, jwtVerify } from 'jose';

export const VERSION = '1.0.0';
export const ISSUER = 'https://login.rante.com/common/v2.0';

/** The cookies the Rante Login browser SDK writes with `serverSide: true` (SameSite=Lax, 10 minutes, Path=/). */
export const BROWSER_SDK_COOKIES = Object.freeze({
  codeVerifier: 'rante_login_pkce',
  state: 'rante_login_state',
  nonce: 'rante_login_nonce'
});

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_LIFETIME_SECONDS = 60; // Rante Login accepts at most 300.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const KEY_PREFIX = /^rk_live_[0-9a-f]{24}$/;
const SCOPES = ['openid', 'profile', 'email', 'phone', 'address', 'rante.organization'];
const PROMPTS = ['none', 'login', 'consent', 'select_account'];
const ERROR_CODE = /^[a-z0-9_]{1,64}$/;

/** Every failure the SDK reports. `code` is stable and safe to show; OAuth errors keep their own codes. */
export class RanteLoginError extends Error {
  constructor(code, message, options = {}) {
    super(message || code, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'RanteLoginError';
    this.code = code;
    if (options.status !== undefined) this.status = options.status;
  }
}

export class RanteLoginClient {
  #clientId;
  #redirectUri;
  #scope;
  #issuer;
  #signingKey;
  #fetch;
  #timeout;
  #clockTolerance;
  #provider;

  /**
   * @param {object} options
   * @param {string} options.clientId The app's Application (client) ID.
   * @param {string} options.redirectUri Exactly as registered on the app.
   * @param {string} [options.scope] Default `openid profile email`.
   * @param {{ keyPrefix: string, privateKey: string | Buffer | KeyObject | object }} [options.signingKey]
   *   Server-side websites: the Signed JWT key linked to the app (its prefix, and the PEM private key). Without it the
   *   client authenticates with PKCE alone (browser-only websites).
   * @param {string} [options.issuer] Default https://login.rante.com/common/v2.0.
   * @param {typeof fetch} [options.fetch] Default the global fetch.
   * @param {number} [options.timeout] Milliseconds for each request to Rante Login. Default 10000.
   * @param {number} [options.clockTolerance] Seconds of clock skew allowed for the ID token. Default 60.
   */
  constructor(options = {}) {
    this.#clientId = normalizeClientId(options.clientId);
    this.#redirectUri = normalizeRedirectUri(options.redirectUri);
    this.#scope = normalizeScope(options.scope ?? 'openid profile email');
    this.#issuer = normalizeIssuer(options.issuer ?? ISSUER);
    this.#signingKey = options.signingKey ? loadSigningKey(options.signingKey) : null;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') throw configError('fetch must be a function (Node.js 18 or later has one).');
    this.#timeout = positiveInteger(options.timeout ?? 10_000, 'timeout');
    this.#clockTolerance = positiveInteger(options.clockTolerance ?? 60, 'clockTolerance');
  }

  get clientId() { return this.#clientId; }
  get redirectUri() { return this.#redirectUri; }
  get scope() { return this.#scope; }
  get issuer() { return this.#issuer; }
  /** `private_key_jwt` with the app's Signed JWT key, or `none` (PKCE alone). */
  get clientAuthentication() { return this.#signingKey ? 'private_key_jwt' : 'none'; }

  /**
   * Starts a sign-in on the server: the URL to send the browser to, and the values to keep (in the server-side
   * session) until the browser comes back to the redirect URI.
   * @returns {Promise<{ url: string, state: string, nonce: string, codeVerifier: string }>}
   */
  async createAuthorizationRequest(options = {}) {
    const nonce = options.nonce === undefined ? randomToken() : checkNonce(options.nonce);
    const prompt = checkPrompt(options.prompt);
    if (options.loginHint !== undefined && (typeof options.loginHint !== 'string' || options.loginHint.length > 256)) {
      throw new RanteLoginError('invalid_request', 'loginHint must be a string of at most 256 characters.');
    }
    if (options.maxAge !== undefined && !(Number.isInteger(options.maxAge) && options.maxAge >= 0)) {
      throw new RanteLoginError('invalid_request', 'maxAge must be a whole number of seconds.');
    }
    const { authorizationEndpoint } = await this.#discover();
    const state = randomToken();
    const codeVerifier = randomToken();
    const url = new URL(authorizationEndpoint);
    url.searchParams.set('client_id', this.#clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', this.#redirectUri);
    url.searchParams.set('scope', this.#scope);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', createHash('sha256').update(codeVerifier).digest('base64url'));
    url.searchParams.set('code_challenge_method', 'S256');
    if (prompt) url.searchParams.set('prompt', prompt);
    if (options.loginHint) url.searchParams.set('login_hint', options.loginHint);
    if (options.maxAge !== undefined) url.searchParams.set('max_age', String(options.maxAge));
    return { url: url.href, state, nonce, codeVerifier };
  }

  /**
   * Finishes a redirect sign-in at the redirect URI: checks the response against the values kept for it, exchanges
   * the code and validates the ID token.
   * @param {URL | URLSearchParams | string | Record<string, string | string[] | undefined>} params The redirect's
   *   query: a URL, its query string, URLSearchParams, or a parsed object such as Express's `req.query`.
   * @param {{ state: string, nonce: string, codeVerifier: string }} expected What createAuthorizationRequest returned,
   *   or `RanteLoginClient.fromBrowserSdkCookies(...)` when the browser SDK started the sign-in.
   */
  async handleCallback(params, expected) {
    const query = readCallbackParams(params);
    if (!expected || !isText(expected.state) || !isText(expected.nonce) || !isText(expected.codeVerifier)) {
      throw new RanteLoginError('missing_transaction', 'No sign-in is in progress for this browser, or it expired.');
    }
    if (!safeEqual(query.state, expected.state)) {
      throw new RanteLoginError('state_mismatch', 'The response does not belong to the sign-in this browser started.');
    }
    if (query.iss !== this.#issuer) {
      throw new RanteLoginError('issuer_mismatch', 'The response did not come from Rante Login.');
    }
    if (query.error) {
      throw new RanteLoginError(ERROR_CODE.test(query.error) ? query.error : 'authorization_failed',
        clean(query.error_description) || query.error);
    }
    if (!query.code) throw new RanteLoginError('invalid_request', 'The response has no code.');

    const tokens = await this.exchangeCode({ code: query.code, codeVerifier: expected.codeVerifier });
    const claims = await this.validateIdToken(tokens.id_token, { nonce: expected.nonce });
    return {
      claims,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      tokenType: tokens.token_type,
      expiresIn: tokens.expires_in,
      scope: tokens.scope
    };
  }

  /** The token request: the code, the PKCE verifier and the app's client authentication. */
  async exchangeCode({ code, codeVerifier } = {}) {
    if (!isText(code) || !isText(codeVerifier)) {
      throw new RanteLoginError('invalid_request', 'code and codeVerifier are required.');
    }
    const { tokenEndpoint } = await this.#discover();
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.#redirectUri,
      client_id: this.#clientId,
      code_verifier: codeVerifier
    });
    if (this.#signingKey) {
      form.set('client_assertion_type', ASSERTION_TYPE);
      form.set('client_assertion', await this.#clientAssertion(tokenEndpoint));
    }
    const response = await this.#send(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: form
    });
    const body = await readJson(response);
    if (!response.ok) {
      throw new RanteLoginError(ERROR_CODE.test(body?.error ?? '') ? body.error : 'token_request_failed',
        clean(body?.error_description) || `The token endpoint answered ${response.status}.`, { status: response.status });
    }
    if (!isObject(body) || !isText(body.id_token) || !isText(body.access_token) ||
      String(body.token_type).toLowerCase() !== 'bearer') {
      throw new RanteLoginError('invalid_token_response', 'The token response has no ID token or no Bearer access token.');
    }
    return body;
  }

  /**
   * Validates an ID token before you trust it: RS256 signature with the key its kid names in Rante Login's JWKS, iss,
   * aud (and azp), exp (with clock skew), iat, sub, and the nonce you expect. Returns its claims.
   */
  async validateIdToken(idToken, { nonce } = {}) {
    if (!isText(nonce)) throw new RanteLoginError('invalid_request', 'The expected nonce is required.');
    if (!isText(idToken)) throw new RanteLoginError('invalid_id_token', 'The ID token is missing.');
    const { jwks } = await this.#discover();
    let payload;
    try {
      ({ payload } = await jwtVerify(idToken, jwks, {
        algorithms: ['RS256'],
        issuer: this.#issuer,
        audience: this.#clientId,
        requiredClaims: ['sub', 'iat', 'exp', 'nonce'],
        clockTolerance: this.#clockTolerance
      }));
    } catch (cause) {
      if (!(cause instanceof joseErrors.JOSEError) || cause.code === 'ERR_JWKS_TIMEOUT') {
        throw new RanteLoginError('network_error', "Rante Login's signing keys could not be fetched.", { cause });
      }
      throw new RanteLoginError('invalid_id_token', `The ID token failed validation (${cause.code}).`, { cause });
    }
    if (!safeEqual(payload.nonce, nonce)) {
      throw new RanteLoginError('invalid_id_token', 'The ID token was issued for another sign-in (nonce).');
    }
    if (payload.azp !== undefined ? payload.azp !== this.#clientId : Array.isArray(payload.aud) && payload.aud.length > 1) {
      throw new RanteLoginError('invalid_id_token', 'The ID token was issued to another app (azp).');
    }
    if (!isText(payload.sub)) throw new RanteLoginError('invalid_id_token', 'The ID token has no sub.');
    return payload;
  }

  /**
   * The person's claims from the userinfo endpoint, with an access token from the code exchange (valid 15 minutes).
   * Pass the ID token's sub as `expectedSubject`: OpenID Connect requires that both match.
   */
  async fetchUserInfo(accessToken, { expectedSubject } = {}) {
    if (!isText(accessToken)) throw new RanteLoginError('invalid_request', 'An access token is required.');
    const { userinfoEndpoint } = await this.#discover();
    const response = await this.#send(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }
    });
    if (response.status === 401) {
      throw new RanteLoginError('invalid_token', 'The access token was refused: it expired, or the person removed their consent.',
        { status: 401 });
    }
    const body = await readJson(response);
    if (!response.ok || !isObject(body) || !isText(body.sub)) {
      throw new RanteLoginError('userinfo_failed', `The userinfo endpoint answered ${response.status}.`, { status: response.status });
    }
    if (expectedSubject !== undefined && body.sub !== expectedSubject) {
      throw new RanteLoginError('userinfo_subject_mismatch', 'The userinfo sub is not the ID token\'s sub.');
    }
    return body;
  }

  /**
   * The values the browser SDK (`serverSide: true`) kept for a redirect sign-in, from the request's cookies: an
   * object such as Express's `req.cookies`, or the Cookie header. Null when any is missing. Clear the three cookies
   * (`BROWSER_SDK_COOKIES`) once you have read them: each sign-in uses them once.
   * @returns {{ state: string, nonce: string, codeVerifier: string } | null}
   */
  static fromBrowserSdkCookies(cookies) {
    const read = typeof cookies === 'string' ? (name) => readCookieHeader(cookies, name) : (name) => cookies?.[name];
    const state = read(BROWSER_SDK_COOKIES.state);
    const nonce = read(BROWSER_SDK_COOKIES.nonce);
    const codeVerifier = read(BROWSER_SDK_COOKIES.codeVerifier);
    return isText(state) && isText(nonce) && isText(codeVerifier) ? { state, nonce, codeVerifier } : null;
  }

  // The discovery document (fetched once; a failed fetch is tried again next time) and a cached JWKS that is fetched
  // again when a token names a kid it doesn't know (key rotation), at most every 30 seconds.
  #discover() {
    this.#provider ??= (async () => {
      const response = await this.#send(`${this.#issuer}/.well-known/openid-configuration`, {
        headers: { Accept: 'application/json' }
      });
      const metadata = await readJson(response);
      if (!response.ok || !isObject(metadata)) {
        throw new RanteLoginError('discovery_failed', `The discovery document answered ${response.status}.`, { status: response.status });
      }
      if (metadata.issuer !== this.#issuer) {
        throw new RanteLoginError('discovery_failed', 'The discovery document names another issuer.');
      }
      for (const name of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']) {
        if (!isText(metadata[name])) throw new RanteLoginError('discovery_failed', `The discovery document has no ${name}.`);
      }
      return {
        authorizationEndpoint: metadata.authorization_endpoint,
        tokenEndpoint: metadata.token_endpoint,
        userinfoEndpoint: metadata.userinfo_endpoint,
        jwks: createRemoteJWKSet(new URL(metadata.jwks_uri), {
          timeoutDuration: this.#timeout,
          [customFetch]: (url, init) => this.#fetch(url, init)
        })
      };
    })();
    this.#provider.catch(() => { this.#provider = undefined; });
    return this.#provider;
  }

  // private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key.
  #clientAssertion(tokenEndpoint) {
    const { key, alg, kid } = this.#signingKey;
    return new SignJWT({})
      .setProtectedHeader({ alg, kid, typ: 'JWT' }) // kid: the Signed JWT key's prefix
      .setIssuer(this.#clientId) // iss and sub: the client ID
      .setSubject(this.#clientId)
      .setAudience(tokenEndpoint) // aud: the token endpoint
      .setIssuedAt()
      .setExpirationTime(`${ASSERTION_LIFETIME_SECONDS}s`)
      .setJti(randomUUID()) // Rante Login accepts each assertion once
      .sign(key);
  }

  async #send(url, init) {
    try {
      return await this.#fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(this.#timeout) });
    } catch (cause) {
      throw new RanteLoginError('network_error', `Rante Login could not be reached (${cause?.name ?? 'error'}).`, { cause });
    }
  }
}

// ------------------------------------------------------------------------------------------------------- helpers

function configError(message) {
  return new RanteLoginError('invalid_configuration', message);
}

function normalizeClientId(value) {
  const clientId = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!GUID.test(clientId)) throw configError("clientId must be the app's Application (client) ID from the Rante Portal.");
  return clientId;
}

// Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower case.
function normalizeRedirectUri(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  const uri = text.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, (prefix) => prefix.toLowerCase());
  let url;
  try { url = new URL(uri); } catch { url = null; }
  const loopback = url && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  if (!url || uri.includes('#') || url.username || url.password || uri.length > 512 ||
    !(url.protocol === 'https:' || (url.protocol === 'http:' && loopback))) {
    throw configError('redirectUri must be the absolute https URI registered on the app (http only for localhost or 127.0.0.1), without a fragment.');
  }
  return uri;
}

function normalizeScope(value) {
  const parts = typeof value === 'string' ? value.split(/\s+/).filter(Boolean) : [];
  const unknown = parts.filter((part) => !SCOPES.includes(part));
  if (!parts.includes('openid') || unknown.length) {
    throw configError(`scope must include openid and only these scopes: ${SCOPES.join(', ')}.`);
  }
  return [...new Set(parts)].join(' ');
}

function normalizeIssuer(value) {
  let url;
  try { url = new URL(value); } catch { url = null; }
  const loopback = url && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  if (!url || !(url.protocol === 'https:' || (url.protocol === 'http:' && loopback)) || url.search || url.hash) {
    throw configError('issuer must be an https URL.');
  }
  return value.replace(/\/+$/, '');
}

function loadSigningKey(signingKey) {
  const { keyPrefix, privateKey } = signingKey;
  if (typeof keyPrefix !== 'string' || !KEY_PREFIX.test(keyPrefix)) {
    throw configError('signingKey.keyPrefix must be the key prefix the Rante Portal shows: rk_live_ and 24 hex digits.');
  }
  let key;
  try {
    key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  } catch (cause) {
    throw new RanteLoginError('invalid_configuration', `signingKey.privateKey is not a private key: ${cause.message}`, { cause });
  }
  const details = key.asymmetricKeyDetails ?? {};
  if (key.type === 'private' && key.asymmetricKeyType === 'rsa' && details.modulusLength >= 2048) {
    return { key, alg: 'RS256', kid: keyPrefix };
  }
  if (key.type === 'private' && key.asymmetricKeyType === 'ec' && details.namedCurve === 'prime256v1') {
    return { key, alg: 'ES256', kid: keyPrefix };
  }
  throw configError('signingKey.privateKey must be an RSA key of at least 2048 bits (RS256) or an EC P-256 key (ES256).');
}

function positiveInteger(value, name) {
  if (!Number.isInteger(value) || value < 0) throw configError(`${name} must be a whole number.`);
  return value;
}

function checkNonce(nonce) {
  if (typeof nonce !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(nonce)) {
    throw new RanteLoginError('invalid_request', 'nonce must be 1 to 256 printable ASCII characters without spaces.');
  }
  return nonce;
}

function checkPrompt(prompt) {
  if (prompt === undefined || prompt === null || prompt === '') return null;
  const parts = typeof prompt === 'string' ? prompt.split(/\s+/).filter(Boolean) : [];
  if (!parts.length || parts.some((part) => !PROMPTS.includes(part)) || (parts.includes('none') && parts.length > 1)) {
    throw new RanteLoginError('invalid_request', `prompt must be ${PROMPTS.join(', ')} (none alone).`);
  }
  return parts.join(' ');
}

// The redirect's parameters. A repeated parameter is refused rather than guessed.
function readCallbackParams(params) {
  let search;
  if (params instanceof URLSearchParams) search = params;
  else if (params instanceof URL) search = params.searchParams;
  else if (typeof params === 'string') {
    search = /^[a-z][a-z0-9+.-]*:/i.test(params) ? new URL(params).searchParams : new URLSearchParams(params.replace(/^\?/, ''));
  } else if (isObject(params)) {
    search = new URLSearchParams();
    for (const [name, value] of Object.entries(params)) {
      for (const item of Array.isArray(value) ? value : [value]) if (typeof item === 'string') search.append(name, item);
    }
  } else {
    throw new RanteLoginError('invalid_request', 'The redirect parameters are missing.');
  }
  const out = {};
  for (const name of ['code', 'state', 'iss', 'error', 'error_description']) {
    const values = search.getAll(name);
    if (values.length > 1) throw new RanteLoginError('invalid_request', `The response repeats ${name}.`);
    out[name] = values[0];
  }
  return out;
}

function readCookieHeader(header, name) {
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

async function readJson(response) {
  const text = await response.text().catch(() => '');
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}

function randomToken() {
  return randomBytes(32).toString('base64url');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function clean(value) {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 300) : '';
}

function isText(value) {
  return typeof value === 'string' && value.length > 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
