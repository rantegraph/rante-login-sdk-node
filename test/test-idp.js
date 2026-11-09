// A local OpenID provider for the tests, shaped like Rante Login: discovery, JWKS, token and userinfo endpoints on
// 127.0.0.1. It issues codes that the tests hand it (standing in for the authorize step), checks each token request
// (PKCE, redirect URI, client authentication, single-use assertions) and signs ID tokens with a key generated for the run.
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { SignJWT, decodeProtectedHeader, exportJWK, jwtVerify } from 'jose';

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export async function startTestIdp() {
  const server = createServer((req, res) => {
    handle(req, res).catch((error) => send(res, 500, { error: 'server_error', error_description: error.message }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const issuer = `${origin}/common/v2.0`;
  const endpoints = {
    authorization: `${origin}/common/oauth2/v2.0/authorize`,
    token: `${origin}/common/oauth2/v2.0/token`,
    userinfo: `${origin}/common/oidc/v2.0/userinfo`,
    jwks: `${origin}/common/discovery/v2.0/keys`
  };
  const signingKeys = [await newSigningKey('test-key-1')];
  const clients = new Map();
  const codes = new Map();
  const accessTokens = new Map();
  const usedAssertions = new Set();
  const requests = [];
  const options = { discoveryIssuer: issuer };
  let lastAssertion = null;

  async function newSigningKey(kid) {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return { kid, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' } };
  }

  async function handle(req, res) {
    const url = new URL(req.url, origin);
    const body = await new Promise((resolve) => {
      let text = '';
      req.on('data', (chunk) => { text += chunk; });
      req.on('end', () => resolve(text));
    });
    const form = req.method === 'POST' ? new URLSearchParams(body) : null;
    requests.push({ method: req.method, path: url.pathname, headers: req.headers, form });
    if (req.method === 'GET' && url.pathname === '/common/v2.0/.well-known/openid-configuration') {
      return send(res, 200, {
        issuer: options.discoveryIssuer,
        authorization_endpoint: endpoints.authorization,
        token_endpoint: endpoints.token,
        userinfo_endpoint: endpoints.userinfo,
        jwks_uri: endpoints.jwks,
        response_types_supported: ['code'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['private_key_jwt', 'none'],
        code_challenge_methods_supported: ['S256'],
        authorization_response_iss_parameter_supported: true
      });
    }
    if (req.method === 'GET' && url.pathname === '/common/discovery/v2.0/keys') {
      return send(res, 200, { keys: signingKeys.map((key) => key.jwk) });
    }
    if (req.method === 'POST' && url.pathname === '/common/oauth2/v2.0/token') return token(res, form, req.headers);
    if (req.method === 'GET' && url.pathname === '/common/oidc/v2.0/userinfo') {
      const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
      const claims = match && accessTokens.get(match[1]);
      if (!claims) {
        res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
        return send(res, 401, {});
      }
      return send(res, 200, claims);
    }
    return send(res, 404, {});
  }

  async function token(res, form, headers) {
    const refuse = (status, error) => send(res, status, { error, error_description: `test IdP: ${error}` });
    const clientId = form.get('client_id');
    const client = clients.get(clientId);
    if (!client || form.has('client_secret') || headers.authorization) return refuse(401, 'invalid_client');
    if (client.type === 'Web') {
      const assertion = form.get('client_assertion');
      if (form.get('client_assertion_type') !== ASSERTION_TYPE || !assertion) return refuse(401, 'invalid_client');
      try {
        const header = decodeProtectedHeader(assertion);
        const key = client.keys.get(header.kid);
        if (!key) return refuse(401, 'invalid_client');
        const { payload } = await jwtVerify(assertion, key, {
          issuer: clientId,
          audience: endpoints.token,
          algorithms: ['RS256', 'ES256'],
          requiredClaims: ['sub', 'jti', 'exp']
        });
        if (payload.sub !== clientId || payload.exp - (payload.iat ?? 0) > 300 || usedAssertions.has(payload.jti)) {
          return refuse(401, 'invalid_client');
        }
        usedAssertions.add(payload.jti);
        lastAssertion = { header, payload };
      } catch {
        return refuse(401, 'invalid_client');
      }
    } else if (form.has('client_assertion') || form.has('client_assertion_type')) {
      return refuse(401, 'invalid_client');
    }
    const code = form.get('code');
    const issued = codes.get(code);
    codes.delete(code);
    const challenge = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
    if (!issued || issued.clientId !== clientId || issued.redirectUri !== form.get('redirect_uri') || issued.codeChallenge !== challenge) {
      return refuse(400, 'invalid_grant');
    }
    const idToken = await mintIdToken({ aud: clientId, azp: clientId, nonce: issued.nonce, ...issued.claims });
    const accessToken = randomUUID();
    accessTokens.set(accessToken, { sub: issued.claims.sub, name: issued.claims.name });
    return send(res, 200, { access_token: accessToken, token_type: 'Bearer', expires_in: 900, id_token: idToken, scope: 'openid profile email' });
  }

  /** An ID token like Rante Login's. Override any claim, or sign with another key, kid or algorithm. */
  async function mintIdToken(claims = {}, { key = signingKeys[0].privateKey, kid = signingKeys[0].kid, alg = 'RS256' } = {}) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ iss: issuer, sub: 'pairwise-subject-1', iat: now, exp: now + 600, auth_time: now, ...claims })
      .setProtectedHeader({ alg, kid, typ: 'JWT' })
      .sign(key);
  }

  return {
    issuer,
    origin,
    endpoints,
    requests,
    options,
    get lastAssertion() { return lastAssertion; },
    /** type: 'Web' (keys: { [prefix]: publicKey }) or 'BrowserOnly'. */
    registerClient(clientId, { type, keys = {} }) {
      clients.set(clientId, { type, keys: new Map(Object.entries(keys)) });
    },
    /** Stands in for the authorize step: a code for these values. */
    issueCode({ clientId, redirectUri, codeChallenge, nonce, claims }) {
      const code = randomBytes(32).toString('hex');
      codes.set(code, { clientId, redirectUri, codeChallenge, nonce, claims });
      return code;
    },
    mintIdToken,
    async addSigningKey(kid) {
      const key = await newSigningKey(kid);
      signingKeys.push(key);
      return key;
    },
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}
