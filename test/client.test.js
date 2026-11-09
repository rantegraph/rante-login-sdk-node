import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { BROWSER_SDK_COOKIES, RanteLoginClient, RanteLoginError } from '../src/index.js';
import { startTestIdp } from './test-idp.js';

const WEB_CLIENT = '11111111-2222-4333-8444-555555555555';
const BROWSER_CLIENT = '66666666-7777-4888-9999-aaaaaaaaaaaa';
// The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
const RSA_PREFIX = 'rk_live_' + '0123456789abcdef01234567';
const EC_PREFIX = 'rk_live_' + '89abcdef0123456789abcdef';
const REDIRECT_URI = 'http://localhost:3000/auth/rante/callback';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const rsaPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' });

let idp;
before(async () => {
  idp = await startTestIdp();
  idp.registerClient(WEB_CLIENT, { type: 'Web', keys: { [RSA_PREFIX]: rsa.publicKey, [EC_PREFIX]: ec.publicKey } });
  idp.registerClient(BROWSER_CLIENT, { type: 'BrowserOnly' });
});
after(() => idp.close());

const webClient = (overrides = {}) => new RanteLoginClient({
  clientId: WEB_CLIENT,
  redirectUri: REDIRECT_URI,
  issuer: idp.issuer,
  signingKey: { keyPrefix: RSA_PREFIX, privateKey: rsaPem },
  ...overrides
});

// The authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce.
function authorize(request, clientId, claims = { sub: 'pairwise-subject-1', name: 'Test Person' }) {
  const url = new URL(request.url);
  return idp.issueCode({
    clientId,
    redirectUri: url.searchParams.get('redirect_uri'),
    codeChallenge: url.searchParams.get('code_challenge'),
    nonce: url.searchParams.get('nonce'),
    claims
  });
}

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof RanteLoginError, `expected a RanteLoginError, got ${error}`);
    assert.equal(error.code, code, error.message);
    return true;
  });
}

describe('createAuthorizationRequest', () => {
  test('builds the authorize URL with PKCE S256, state and nonce', async () => {
    const request = await webClient().createAuthorizationRequest();
    const url = new URL(request.url);
    assert.equal(`${url.origin}${url.pathname}`, idp.endpoints.authorization);
    const params = Object.fromEntries(url.searchParams);
    assert.deepEqual(Object.keys(params).sort(),
      ['client_id', 'code_challenge', 'code_challenge_method', 'nonce', 'redirect_uri', 'response_type', 'scope', 'state']);
    assert.equal(params.client_id, WEB_CLIENT);
    assert.equal(params.response_type, 'code');
    assert.equal(params.redirect_uri, REDIRECT_URI);
    assert.equal(params.scope, 'openid profile email');
    assert.equal(params.code_challenge_method, 'S256');
    assert.equal(params.code_challenge, createHash('sha256').update(request.codeVerifier).digest('base64url'));
    assert.equal(params.state, request.state);
    assert.equal(params.nonce, request.nonce);
    assert.match(request.codeVerifier, /^[A-Za-z0-9_-]{43}$/);
    const other = await webClient().createAuthorizationRequest();
    assert.notEqual(other.state, request.state);
    assert.notEqual(other.nonce, request.nonce);
    assert.notEqual(other.codeVerifier, request.codeVerifier);
  });

  test('passes a nonce, prompt, login hint and max age, and refuses bad ones', async () => {
    const client = webClient();
    const request = await client.createAuthorizationRequest({ nonce: 'server-nonce-1', prompt: 'login', loginHint: 'person@example.com', maxAge: 0 });
    const params = new URL(request.url).searchParams;
    assert.equal(request.nonce, 'server-nonce-1');
    assert.equal(params.get('nonce'), 'server-nonce-1');
    assert.equal(params.get('prompt'), 'login');
    assert.equal(params.get('login_hint'), 'person@example.com');
    assert.equal(params.get('max_age'), '0');
    await rejects(client.createAuthorizationRequest({ nonce: 'has space' }), 'invalid_request');
    await rejects(client.createAuthorizationRequest({ prompt: 'none login' }), 'invalid_request');
    await rejects(client.createAuthorizationRequest({ prompt: 'always' }), 'invalid_request');
    await rejects(client.createAuthorizationRequest({ maxAge: 1.5 }), 'invalid_request');
  });
});

describe('handleCallback', () => {
  test('a server-side website signs in with a private_key_jwt RS256 assertion', async () => {
    const client = webClient();
    assert.equal(client.clientAuthentication, 'private_key_jwt');
    const request = await client.createAuthorizationRequest();
    const code = authorize(request, WEB_CLIENT);
    const result = await client.handleCallback(`${REDIRECT_URI}?code=${code}&state=${request.state}&iss=${encodeURIComponent(idp.issuer)}`, request);
    assert.equal(result.claims.sub, 'pairwise-subject-1');
    assert.equal(result.claims.name, 'Test Person');
    assert.equal(result.claims.nonce, request.nonce);
    assert.equal(result.tokenType, 'Bearer');
    assert.ok(result.idToken && result.accessToken);

    const form = idp.requests.findLast((r) => r.path.endsWith('/token')).form;
    assert.equal(form.get('grant_type'), 'authorization_code');
    assert.equal(form.get('redirect_uri'), REDIRECT_URI);
    assert.equal(form.get('client_id'), WEB_CLIENT);
    assert.equal(form.get('code_verifier'), request.codeVerifier);
    assert.equal(form.get('client_assertion_type'), 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    const { header, payload } = idp.lastAssertion;
    assert.equal(header.alg, 'RS256');
    assert.equal(header.kid, RSA_PREFIX);
    assert.equal(payload.iss, WEB_CLIENT);
    assert.equal(payload.sub, WEB_CLIENT);
    assert.equal(payload.aud, idp.endpoints.token);
    assert.ok(payload.exp - payload.iat <= 300);
    assert.match(payload.jti, /^[0-9a-f-]{36}$/);
  });

  test('ES256 keys sign ES256 assertions', async () => {
    const client = webClient({ signingKey: { keyPrefix: EC_PREFIX, privateKey: ec.privateKey } });
    const request = await client.createAuthorizationRequest();
    const result = await client.handleCallback({ code: authorize(request, WEB_CLIENT), state: request.state, iss: idp.issuer }, request);
    assert.equal(result.claims.sub, 'pairwise-subject-1');
    assert.equal(idp.lastAssertion.header.alg, 'ES256');
    assert.equal(idp.lastAssertion.header.kid, EC_PREFIX);
  });

  test('a browser-only website sends no client credential (PKCE alone)', async () => {
    const client = new RanteLoginClient({ clientId: BROWSER_CLIENT, redirectUri: REDIRECT_URI, issuer: idp.issuer });
    assert.equal(client.clientAuthentication, 'none');
    const request = await client.createAuthorizationRequest();
    const params = new URLSearchParams({ code: authorize(request, BROWSER_CLIENT), state: request.state, iss: idp.issuer });
    const result = await client.handleCallback(params, request);
    assert.equal(result.claims.aud, BROWSER_CLIENT);
    const form = idp.requests.findLast((r) => r.path.endsWith('/token')).form;
    assert.equal(form.has('client_assertion'), false);
    assert.equal(form.has('client_assertion_type'), false);
    assert.equal(form.has('client_secret'), false);
  });

  test('refuses a wrong state, a missing or wrong iss, repeated parameters and a missing transaction before any token request', async () => {
    const client = webClient();
    const request = await client.createAuthorizationRequest();
    const code = authorize(request, WEB_CLIENT);
    const before = idp.requests.length;
    await rejects(client.handleCallback({ code, state: 'another', iss: idp.issuer }, request), 'state_mismatch');
    await rejects(client.handleCallback({ code, state: request.state }, request), 'issuer_mismatch');
    await rejects(client.handleCallback({ code, state: request.state, iss: 'https://login.example.com/common/v2.0' }, request), 'issuer_mismatch');
    await rejects(client.handleCallback({ code, state: [request.state, request.state], iss: idp.issuer }, request), 'invalid_request');
    await rejects(client.handleCallback({ code, state: request.state, iss: idp.issuer }, null), 'missing_transaction');
    await rejects(client.handleCallback({ code, state: request.state, iss: idp.issuer }, { state: request.state }), 'missing_transaction');
    await rejects(client.handleCallback({ state: request.state, iss: idp.issuer }, request), 'invalid_request');
    assert.equal(idp.requests.length, before);
  });

  test("reports the provider's error, such as a cancelled consent", async () => {
    const client = webClient();
    const request = await client.createAuthorizationRequest();
    await assert.rejects(
      client.handleCallback({ error: 'access_denied', error_description: 'The person cancelled the sign-in.', state: request.state, iss: idp.issuer }, request),
      (error) => error.code === 'access_denied' && error.message === 'The person cancelled the sign-in.');
  });

  test('token endpoint errors keep their code and status: a code works once', async () => {
    const client = webClient();
    const request = await client.createAuthorizationRequest();
    const params = { code: authorize(request, WEB_CLIENT), state: request.state, iss: idp.issuer };
    await client.handleCallback(params, request);
    await assert.rejects(client.handleCallback(params, request), (error) => error.code === 'invalid_grant' && error.status === 400);
  });

  test('a key that is not linked to the app gets invalid_client', async () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const client = webClient({ signingKey: { keyPrefix: 'rk_live_' + 'f'.repeat(24), privateKey: other.privateKey } });
    const request = await client.createAuthorizationRequest();
    await assert.rejects(client.handleCallback({ code: authorize(request, WEB_CLIENT), state: request.state, iss: idp.issuer }, request),
      (error) => error.code === 'invalid_client' && error.status === 401);
  });
});

describe('validateIdToken', () => {
  const nonce = 'expected-nonce';
  const valid = (claims = {}) => idp.mintIdToken({ aud: WEB_CLIENT, azp: WEB_CLIENT, nonce, ...claims });

  test('accepts a valid ID token and returns its claims', async () => {
    const claims = await webClient().validateIdToken(await valid({ name: 'Test Person' }), { nonce });
    assert.equal(claims.sub, 'pairwise-subject-1');
    assert.equal(claims.name, 'Test Person');
  });

  test('refuses tokens that fail any check', async () => {
    const client = webClient();
    const now = Math.floor(Date.now() / 1000);
    const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const unsigned = (header, payload) =>
      `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    const body = { iss: idp.issuer, sub: 's', aud: WEB_CLIENT, azp: WEB_CLIENT, iat: now, exp: now + 600, nonce };
    const hs256 = (() => {
      const input = unsigned({ alg: 'HS256', kid: 'test-key-1', typ: 'JWT' }, body);
      return `${input}.${createHmac('sha256', 'secret').update(input).digest('base64url')}`;
    })();
    const cases = {
      'another key, same kid': await idp.mintIdToken({ aud: WEB_CLIENT, nonce }, { key: stranger.privateKey }),
      'unknown kid': await idp.mintIdToken({ aud: WEB_CLIENT, nonce }, { key: stranger.privateKey, kid: 'not-a-rante-key' }),
      'another issuer': await valid({ iss: 'https://login.example.com/common/v2.0' }),
      'another audience': await valid({ aud: '99999999-2222-4333-8444-555555555555', azp: undefined }),
      'another azp': await valid({ azp: '99999999-2222-4333-8444-555555555555' }),
      expired: await valid({ iat: now - 1200, exp: now - 600 }),
      'another nonce': await valid({ nonce: 'other-nonce' }),
      'no nonce': await valid({ nonce: undefined }),
      'no sub': await valid({ sub: undefined }),
      HS256: hs256,
      'alg none': `${unsigned({ alg: 'none', typ: 'JWT' }, body)}.`,
      'not a JWT': 'not-a-jwt'
    };
    for (const [name, token] of Object.entries(cases)) {
      await assert.rejects(client.validateIdToken(token, { nonce }), (error) => {
        assert.equal(error.code, 'invalid_id_token', `${name}: ${error.message}`);
        return true;
      }, name);
    }
    await rejects(client.validateIdToken(await valid(), {}), 'invalid_request');
  });

  test('allows a minute of clock skew', async () => {
    const now = Math.floor(Date.now() / 1000);
    await webClient().validateIdToken(await valid({ iat: now - 630, exp: now - 30 }), { nonce });
  });

  test('uses a key that Rante Login adds later', async () => {
    const added = await idp.addSigningKey('test-key-2');
    const client = webClient();
    const token = await idp.mintIdToken({ aud: WEB_CLIENT, nonce }, { key: added.privateKey, kid: 'test-key-2' });
    assert.equal((await client.validateIdToken(token, { nonce })).sub, 'pairwise-subject-1');
  });
});

describe('fetchUserInfo', () => {
  test("returns the person's claims and checks the sub", async () => {
    const client = webClient();
    const request = await client.createAuthorizationRequest();
    const result = await client.handleCallback({ code: authorize(request, WEB_CLIENT), state: request.state, iss: idp.issuer }, request);
    const userinfo = await client.fetchUserInfo(result.accessToken, { expectedSubject: result.claims.sub });
    assert.deepEqual(userinfo, { sub: 'pairwise-subject-1', name: 'Test Person' });
    assert.equal(idp.requests.findLast((r) => r.path.endsWith('/userinfo')).headers.authorization, `Bearer ${result.accessToken}`);
    await rejects(client.fetchUserInfo(result.accessToken, { expectedSubject: 'someone-else' }), 'userinfo_subject_mismatch');
    await assert.rejects(client.fetchUserInfo('expired-or-unknown'), (error) => error.code === 'invalid_token' && error.status === 401);
  });
});

describe('fromBrowserSdkCookies', () => {
  test('reads the three cookies from an object or a Cookie header', () => {
    const expected = { state: 's1', nonce: 'n1', codeVerifier: 'v'.repeat(43) };
    assert.deepEqual(RanteLoginClient.fromBrowserSdkCookies({
      [BROWSER_SDK_COOKIES.state]: 's1', [BROWSER_SDK_COOKIES.nonce]: 'n1', [BROWSER_SDK_COOKIES.codeVerifier]: 'v'.repeat(43)
    }), expected);
    assert.deepEqual(RanteLoginClient.fromBrowserSdkCookies(
      `other=1; rante_login_pkce=${'v'.repeat(43)}; rante_login_state=s1; rante_login_nonce=n1`), expected);
    assert.equal(RanteLoginClient.fromBrowserSdkCookies({ rante_login_state: 's1' }), null);
    assert.equal(RanteLoginClient.fromBrowserSdkCookies(undefined), null);
  });
});

describe('configuration', () => {
  test('refuses bad settings', () => {
    const base = { clientId: WEB_CLIENT, redirectUri: REDIRECT_URI };
    const weakRsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    const bad = {
      'client ID': { ...base, clientId: 'my-app' },
      'http redirect URI': { ...base, redirectUri: 'http://shop.example.com/callback' },
      'redirect URI with a fragment': { ...base, redirectUri: 'https://shop.example.com/callback#x' },
      'scope without openid': { ...base, scope: 'profile email' },
      'unknown scope': { ...base, scope: 'openid offline_access' },
      'key prefix': { ...base, signingKey: { keyPrefix: 'my-key', privateKey: rsaPem } },
      'RSA 1024': { ...base, signingKey: { keyPrefix: RSA_PREFIX, privateKey: weakRsa } },
      'EC P-384': { ...base, signingKey: { keyPrefix: RSA_PREFIX, privateKey: p384 } },
      'a public key': { ...base, signingKey: { keyPrefix: RSA_PREFIX, privateKey: rsa.publicKey.export({ type: 'spki', format: 'pem' }) } },
      'http issuer': { ...base, issuer: 'http://login.example.com/common/v2.0' }
    };
    for (const [name, options] of Object.entries(bad)) {
      assert.throws(() => new RanteLoginClient(options), (error) => error.code === 'invalid_configuration', name);
    }
  });

  test('normalizes the client ID and the redirect URI scheme and host like the browser SDK', () => {
    const client = new RanteLoginClient({ clientId: WEB_CLIENT.toUpperCase(), redirectUri: 'HTTPS://Shop.Example.com/Auth/Callback' });
    assert.equal(client.clientId, WEB_CLIENT);
    assert.equal(client.redirectUri, 'https://shop.example.com/Auth/Callback');
    assert.equal(client.issuer, 'https://login.rante.com/common/v2.0');
  });

  test('refuses a discovery document that names another issuer', async () => {
    idp.options.discoveryIssuer = 'https://login.example.com/common/v2.0';
    try {
      await rejects(webClient().createAuthorizationRequest(), 'discovery_failed');
    } finally {
      idp.options.discoveryIssuer = idp.issuer;
    }
  });

  test('reports an unreachable provider as network_error', async () => {
    const client = webClient({ issuer: 'http://127.0.0.1:9/common/v2.0', timeout: 2000 });
    await rejects(client.createAuthorizationRequest(), 'network_error');
  });
});
