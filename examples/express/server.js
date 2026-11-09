// Sign in with Rante: an Express website that signs people in with the Rante Login SDK for Node.js.
//
// Three ways in, all finished and checked on this server:
// - "Sign in with Rante" button (public/signin.js): the browser SDK with serverSide: true. In Chrome and Edge it uses
//   FedCM and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the
//   redirect URI with the SDK's rante_login_* cookies.
// - "Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here (createAuthorizationRequest)
//   and keeps its state, nonce and PKCE verifier in the session.
// - Either redirect ends at the redirect URI, where handleCallback exchanges the code (private_key_jwt or PKCE alone)
//   and validates the ID token.

import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import cookieParser from 'cookie-parser';
import express from 'express';
import session from 'express-session';
import { BROWSER_SDK_COOKIES, RanteLoginClient, RanteLoginError } from 'rante-login-sdk-node';

const SDK_SRC = 'https://login.rante.com/sdk/v1/rante-login.js';
const SDK_INTEGRITY = 'sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf';
const SESSION_COOKIE = 'rante_express_session';

// This website's own accounts. A person's first "Sign in with Rante" here is their sign-up: the account is created from
// the claims they agreed to share, and every later sign-in finds it by `sub`. A real website keeps accounts in its
// database; this example keeps them in memory, so they're gone when the server restarts.
const accounts = new Map();

function registerOrFind(claims) {
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  let account = accounts.get(claims.sub);
  const created = !account;
  if (created) {
    account = { id: randomUUID(), sub: claims.sub, name: null, email: null, createdAt: now };
    accounts.set(claims.sub, account);
  }
  // Keep the details the person shares this time. Rante shares an email only once it's verified.
  account.name = claims.name ?? account.name;
  account.email = claims.email ?? account.email;
  account.lastSignInAt = now;
  return { account, created };
}

const env = process.env;
if (Boolean(env.RANTE_LOGIN_KEY_PREFIX) !== Boolean(env.RANTE_LOGIN_PRIVATE_KEY_FILE)) {
  exit('Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).');
}
let rante;
try {
  rante = new RanteLoginClient({
    clientId: env.RANTE_LOGIN_CLIENT_ID,
    redirectUri: env.RANTE_LOGIN_REDIRECT_URI || 'http://localhost:3000/auth/rante/callback',
    scope: env.RANTE_LOGIN_SCOPE || undefined,
    signingKey: env.RANTE_LOGIN_PRIVATE_KEY_FILE
      ? { keyPrefix: env.RANTE_LOGIN_KEY_PREFIX, privateKey: readFileSync(env.RANTE_LOGIN_PRIVATE_KEY_FILE) }
      : undefined
  });
} catch (error) {
  exit(error.message);
}
const redirect = new URL(rante.redirectUri);
const siteOrigin = redirect.origin;
const callbackPath = redirect.pathname;
if (['/', '/auth/rante/sign-in', '/auth/rante/fedcm', '/auth/sign-out', '/userinfo'].includes(callbackPath)) {
  exit('Give RANTE_LOGIN_REDIRECT_URI a path of its own, for example /auth/rante/callback.');
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' https://login.rante.com", // the browser SDK, pinned by its integrity hash
      "connect-src 'self' https://login.rante.com", // FedCM fetches the identity provider's configuration
      "img-src 'self' data:",
      "style-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join('; '),
    'Referrer-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff'
  });
  next();
});
app.use(express.static(fileURLToPath(new URL('./public/', import.meta.url)), { index: false }));
app.use(cookieParser());
app.use(session({
  name: SESSION_COOKIE,
  secret: env.SESSION_SECRET || randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: siteOrigin.startsWith('https:'), maxAge: 8 * 60 * 60 * 1000 }
}));

app.get('/', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (req.session.user) {
    res.send(signedInPage(req.session.user));
    return;
  }
  // FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep it in
  // the session. The browser SDK sends the same nonce in its redirect flow.
  req.session.ranteNonce ??= randomBytes(32).toString('base64url');
  res.send(signInPage(req.session.ranteNonce));
});

// The server starts the sign-in: no JavaScript needed.
app.get('/auth/rante/sign-in', async (req, res) => {
  try {
    const request = await rante.createAuthorizationRequest();
    req.session.ranteRequest = { state: request.state, nonce: request.nonce, codeVerifier: request.codeVerifier };
    await save(req);
    res.redirect(303, request.url);
  } catch (error) {
    sendError(res, error);
  }
});

// The redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...).
app.get(callbackPath, async (req, res) => {
  // A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
  const started = req.session.ranteRequest;
  delete req.session.ranteRequest;
  const fromBrowser = RanteLoginClient.fromBrowserSdkCookies(req.cookies);
  for (const name of Object.values(BROWSER_SDK_COOKIES)) res.clearCookie(name, { path: '/' });
  const byServer = Boolean(started) && started.state === req.query.state;
  try {
    const result = await rante.handleCallback(req.query, byServer ? started : fromBrowser ?? started);
    await startSession(req, {
      claims: result.claims,
      accessToken: result.accessToken,
      method: `${byServer ? 'Redirect started by the server' : 'Redirect started by the browser SDK'}, ${rante.clientAuthentication}`
    });
    res.redirect(303, '/');
  } catch (error) {
    sendError(res, error);
  }
});

// FedCM: the page posts the ID token the browser's account dialog returned.
app.post('/auth/rante/fedcm', express.json({ limit: '16kb' }), async (req, res) => {
  if (req.get('origin') !== siteOrigin) {
    res.status(403).json({ error: 'origin_not_allowed' });
    return;
  }
  try {
    const nonce = req.session.ranteNonce;
    if (!nonce) throw new RanteLoginError('missing_transaction', 'This browser session has no sign-in nonce. Reload the page.');
    const claims = await rante.validateIdToken(req.body?.idToken, { nonce });
    await startSession(req, { claims, method: 'FedCM' });
    res.status(204).end();
  } catch (error) {
    const known = error instanceof RanteLoginError;
    console.warn('FedCM sign-in failed:', known ? `${error.code}: ${error.message}` : error);
    res.status(known ? 400 : 500).json({ error: known ? error.code : 'server_error' });
  }
});

// The person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange (15 minutes).
app.get('/userinfo', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const user = req.session.user;
  if (!user) {
    res.redirect(303, '/');
    return;
  }
  if (!user.accessToken) {
    res.send(page('Userinfo', '<h1>Userinfo</h1><p>FedCM sign-ins return only an ID token, so there is no access token to call userinfo with.</p><p><a href="/">Back</a></p>'));
    return;
  }
  try {
    const claims = await rante.fetchUserInfo(user.accessToken, { expectedSubject: user.claims.sub });
    res.send(page('Userinfo', `<h1>Userinfo</h1><p>From ${escapeHtml('GET https://login.rante.com/common/oidc/v2.0/userinfo')}:</p>${claimsTable(claims)}<p><a href="/">Back</a></p>`));
  } catch (error) {
    sendError(res, error);
  }
});

app.post('/auth/sign-out', (req, res, next) => {
  if (req.get('origin') && req.get('origin') !== siteOrigin) {
    res.status(403).end();
    return;
  }
  // Signs out of this website only; the person stays signed in to Rante.
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.redirect(303, '/');
  });
});

app.listen(Number(env.PORT || redirect.port || 3000), env.HOST || '127.0.0.1', (error) => {
  if (error) throw error;
  console.log(`Sign in with Rante (Express example): ${siteOrigin}/ - client ${rante.clientId}, ${rante.clientAuthentication}`);
});

// ------------------------------------------------------------------------------------------------------- helpers

function exit(message) {
  console.error(message);
  process.exit(1);
}

function save(req) {
  return new Promise((resolve, reject) => req.session.save((error) => (error ? reject(error) : resolve())));
}

// A new session for the person who signed in: its ID changes, so a session fixed before sign-in is worthless. The
// sign-in also creates or finds their account on this website.
function startSession(req, user) {
  const { created } = registerOrFind(user.claims);
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) return reject(error);
      req.session.user = { ...user, newAccount: created, signedInAt: new Date().toISOString() };
      req.session.save((saveError) => (saveError ? reject(saveError) : resolve()));
    });
  });
}

function sendError(res, error) {
  const known = error instanceof RanteLoginError;
  // Log the reason, never the code, the cookies or a token.
  console.warn('Sign-in failed:', known ? `${error.code}: ${error.message}` : error);
  const message = error.code === 'access_denied'
    ? 'The sign-in was cancelled on the Rante Login page.'
    : known ? error.message : 'Something went wrong on this server. Its log has the details.';
  res.status(known ? 400 : 500).send(page('Sign-in failed', `
    <h1>Sign-in failed</h1>
    <p class="error"><code>${escapeHtml(known ? error.code : 'server_error')}</code> ${escapeHtml(message)}</p>
    <p><a href="/">Try again</a></p>`));
}

function signInPage(nonce) {
  return page('Sign in with Rante', `
    <h1>Sign in with Rante</h1>
    <p>Express example of the Rante Login SDK for Node.js: the server finishes the sign-in and validates the ID token.</p>
    <div id="rante-signin"
         data-client-id="${escapeHtml(rante.clientId)}"
         data-redirect-uri="${escapeHtml(rante.redirectUri)}"
         data-scope="${escapeHtml(rante.scope)}"
         data-nonce="${escapeHtml(nonce)}"></div>
    <p id="rante-signin-status" role="status"></p>
    <p><a href="/auth/rante/sign-in">Sign in without JavaScript</a> (the server starts the sign-in)</p>
    <script src="${SDK_SRC}" integrity="${SDK_INTEGRITY}" crossorigin="anonymous"></script>
    <script src="/signin.js"></script>`);
}

function signedInPage(user) {
  return page('Signed in', `
    <h1>Signed in${user.claims.name ? ` as ${escapeHtml(user.claims.name)}` : ''}</h1>
    <p>Signed in with: <strong>${escapeHtml(user.method)}</strong>, ${escapeHtml(user.signedInAt)}</p>
    ${accountSection(user)}
    <h2>ID token</h2>
    <p>This server validated the ID token below. Use <code>sub</code> as the person's ID on this website: it is
       pairwise, so other organizations' apps see a different value.</p>
    ${claimsTable(user.claims)}
    <p><a href="/userinfo">Show userinfo</a></p>
    <form method="post" action="/auth/sign-out"><button type="submit">Sign out</button></form>`);
}

function accountSection(user) {
  const account = accounts.get(user.claims.sub);
  if (!account) {
    return `
    <h2>Your account on this website</h2>
    <p>Not found: this example keeps accounts in memory, and the server has restarted since you signed in. Sign out and
       in again.</p>`;
  }
  return `
    <h2>Your account on this website</h2>
    <p>${user.newAccount
      ? 'Created at this sign-in from your Rante account: no separate sign-up form, and no password for this website.'
      : 'Welcome back: this sign-in found your account by its Rante ID.'}</p>
    <table><tbody>
      <tr><th>Account ID</th><td>${escapeHtml(account.id)}</td></tr>
      <tr><th>Linked Rante ID (<code>sub</code>)</th><td>${escapeHtml(account.sub)}</td></tr>
      <tr><th>Name</th><td>${escapeHtml(account.name ?? 'not shared')}</td></tr>
      <tr><th>Email</th><td>${escapeHtml(account.email ?? "not shared (Rante shares an email only once it's verified)")}</td></tr>
      <tr><th>Created</th><td>${escapeHtml(account.createdAt)}</td></tr>
      <tr><th>Last sign-in</th><td>${escapeHtml(account.lastSignInAt)}</td></tr>
    </tbody></table>
    <p>This example keeps accounts in memory. A real website stores them in its database, keyed by <code>sub</code>.</p>`;
}

function claimsTable(claims) {
  const rows = Object.entries(claims)
    .map(([name, value]) => `<tr><th><code>${escapeHtml(name)}</code></th><td>${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value))}</td></tr>`)
    .join('');
  return `<table><tbody>${rows}</tbody></table>`;
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Express example</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <main>${body}
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
