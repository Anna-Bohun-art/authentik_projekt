import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export interface OidcConfig {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

/**
 * The Authorization Code request (RFC 6749 §4.1.1) plus the PKCE parameters
 * (RFC 7636 §4.3). This is a GET the browser is redirected to — nothing here
 * is secret, which is exactly why the actual `codeVerifier` never appears in
 * it, only its SHA-256 hash.
 */
export function buildAuthorizationUrl(
  cfg: OidcConfig,
  params: { state: string; codeChallenge: string; scope: string },
): string {
  const url = new URL(cfg.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

interface TokenEndpointResponse {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

export interface TokenResult {
  accessToken: string;
  idToken?: string;
  expiresIn: number;
  scope?: string;
}

/**
 * The Authorization Code grant's token request (RFC 6749 §4.1.3), extended
 * with `code_verifier` (RFC 7636 §4.5). authentik checks that
 * SHA-256(code_verifier) equals the `code_challenge` this same `code` was
 * issued with — that check, not the client_secret, is what proves this
 * request came from whoever started the login.
 */
export async function exchangeCodeForTokens(
  cfg: OidcConfig,
  params: { code: string; codeVerifier: string },
): Promise<TokenResult> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    code_verifier: params.codeVerifier,
  });

  const res = await fetch(cfg.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`token exchange failed (${res.status}): ${await res.text()}`);
  }
  const json = (await res.json()) as TokenEndpointResponse;
  return {
    accessToken: json.access_token,
    idToken: json.id_token,
    expiresIn: json.expires_in,
    scope: json.scope,
  };
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function jwksFor(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

/**
 * Verifies the ID token exactly the way
 * soap-gateway/src/auth/tokens.ts#createTokenVerifier verifies access tokens
 * — signature via JWKS, `iss`, `aud`, `exp` — with one deliberate difference:
 * here `aud` must be *this client's* client_id (OIDC Core §3.1.3.7), because
 * an ID token asserts "this user authenticated, for you, this client" to the
 * client itself. An access token's `aud` instead names the resource server
 * it may be presented to (soap-gateway) — same shape of check, different
 * question being answered.
 */
export async function verifyIdToken(cfg: OidcConfig, idToken: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, jwksFor(cfg.jwksUri), {
    issuer: cfg.issuer,
    audience: cfg.clientId,
    requiredClaims: ['iss', 'aud', 'exp', 'sub'],
  });
  return payload;
}
