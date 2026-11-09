import type { KeyObject } from 'node:crypto';

export declare const VERSION: string;
/** https://login.rante.com/common/v2.0 */
export declare const ISSUER: string;
/** The cookies the Rante Login browser SDK writes with `serverSide: true`. */
export declare const BROWSER_SDK_COOKIES: Readonly<{
  codeVerifier: 'rante_login_pkce';
  state: 'rante_login_state';
  nonce: 'rante_login_nonce';
}>;

/** Every failure the SDK reports. OAuth errors (access_denied, invalid_grant, invalid_client, ...) keep their codes. */
export declare class RanteLoginError extends Error {
  readonly name: 'RanteLoginError';
  readonly code: string;
  /** The HTTP status, for errors that came from Rante Login. */
  readonly status?: number;
}

export interface SigningKey {
  /** The Signed JWT key's prefix as the Rante Portal shows it (rk_live_ and 24 hex digits). Sent as the assertion's kid. */
  keyPrefix: string;
  /** The PEM private key (RSA of at least 2048 bits for RS256, or EC P-256 for ES256), or a KeyObject. */
  privateKey: string | Buffer | KeyObject | { key: string | Buffer; passphrase?: string; format?: 'pem' | 'der'; type?: 'pkcs1' | 'pkcs8' | 'sec1' };
}

export interface RanteLoginClientOptions {
  /** The app's Application (client) ID. */
  clientId: string;
  /** Exactly as registered on the app. */
  redirectUri: string;
  /** Default `openid profile email`. */
  scope?: string;
  /** Server-side websites: the Signed JWT key linked to the app. Without it, PKCE alone (browser-only websites). */
  signingKey?: SigningKey;
  /** Default https://login.rante.com/common/v2.0. */
  issuer?: string;
  fetch?: typeof fetch;
  /** Milliseconds for each request to Rante Login. Default 10000. */
  timeout?: number;
  /** Seconds of clock skew allowed for the ID token. Default 60. */
  clockTolerance?: number;
}

export interface AuthorizationRequestOptions {
  /** Your own nonce. Default: a random one. */
  nonce?: string;
  prompt?: 'none' | 'login' | 'consent' | 'select_account' | string;
  loginHint?: string;
  /** Maximum authentication age, in seconds. */
  maxAge?: number;
}

/** Keep state, nonce and codeVerifier on the server (in the session) until the browser comes back. */
export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface ExpectedTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface IdTokenClaims {
  iss: string;
  /** Pairwise: the same for your organization's apps, different for others. */
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce: string;
  auth_time?: number;
  azp?: string;
  amr?: string[];
  tid?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  /** Only once the person has verified it. */
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: { formatted?: string; [field: string]: unknown };
  birthdate?: string;
  picture?: string;
  rante_org?: unknown;
  roles?: string[];
  [claim: string]: unknown;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  id_token: string;
  scope?: string;
}

export interface SignInResult {
  claims: IdTokenClaims;
  idToken: string;
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  scope?: string;
}

export type CallbackParams = URL | URLSearchParams | string | Record<string, string | string[] | undefined>;

export declare class RanteLoginClient {
  constructor(options: RanteLoginClientOptions);
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
  readonly issuer: string;
  readonly clientAuthentication: 'private_key_jwt' | 'none';
  createAuthorizationRequest(options?: AuthorizationRequestOptions): Promise<AuthorizationRequest>;
  handleCallback(params: CallbackParams, expected: ExpectedTransaction | null | undefined): Promise<SignInResult>;
  exchangeCode(input: { code: string; codeVerifier: string }): Promise<TokenResponse>;
  validateIdToken(idToken: string, options: { nonce: string }): Promise<IdTokenClaims>;
  fetchUserInfo(accessToken: string, options?: { expectedSubject?: string }): Promise<{ sub: string; [claim: string]: unknown }>;
  static fromBrowserSdkCookies(cookies: string | Record<string, string | undefined> | null | undefined): ExpectedTransaction | null;
}
