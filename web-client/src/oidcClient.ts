import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { z } from 'zod';

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

/**
 * RFC 6749 §5.1. Parsed rather than cast: a missing or non-numeric
 * `expires_in` would otherwise turn `expiresAt` into NaN, and
 * `Date.now() >= NaN` is always false — a session that never expires.
 */
const TokenEndpointResponse = z.object({
  access_token: z.string().min(1),
  id_token: z.string().min(1).optional(),
  token_type: z.string().refine((t) => t.toLowerCase() === 'bearer', 'expected token_type "Bearer"'),
  expires_in: z.number().int().positive(),
  scope: z.string().optional(),
});

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
  const parsed = TokenEndpointResponse.safeParse(await res.json());
  if (!parsed.success) {
    const details = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`unexpected token response: ${details}`);
  }
  const json = parsed.data;
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
 * — signature via JWKS, `iss`, `aud`, `exp`. Here `aud` must be *this
 * client's* client_id (OIDC Core §3.1.3.7): an ID token tells the client
 * "this user authenticated, for you".
 *
 * In this demo that client_id is `soap-gateway`, the same value the gateway
 * expects as an access token's `aud`: one authentik provider serves the
 * machine client, this web client and the gateway, and authentik always sets
 * an access token's `aud` to the issuing provider's client_id. So `aud` alone
 * cannot tell the two token types apart. Nor can `scope`: authentik puts the
 * granted scopes into the ID token too. What keeps an ID token out of the
 * gateway is that it requires an `azp` claim, which authentik only sets on
 * access tokens (soap-gateway/src/auth/tokens.ts). A setup with a separate
 * provider per client would give the ID token its own `aud`, but the gateway
 * would then have to accept that client_id as an audience too, which closes
 * nothing.
 */
export async function verifyIdToken(cfg: OidcConfig, idToken: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, jwksFor(cfg.jwksUri), {
    issuer: cfg.issuer,
    audience: cfg.clientId,
    // authentik signs with the provider's RSA key; pinning the algorithm means
    // a token can never pick a weaker one via its own header.
    algorithms: ['RS256'],
    requiredClaims: ['iss', 'aud', 'exp', 'sub'],
  });
  return payload;
}
