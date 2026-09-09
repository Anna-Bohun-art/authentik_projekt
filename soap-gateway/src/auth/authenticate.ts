import { UnauthorizedError } from '../soap/faults.js';
import { extractHttpBearer, extractWsSecurityToken } from './wsSecurity.js';
import type { TokenClaims, TokenVerifier } from './tokens.js';

export type TokenTransport = 'http-bearer' | 'ws-security';

export interface AuthContext {
  claims: TokenClaims;
  transport: TokenTransport;
  /** Best-effort human identity for logging / audit. */
  subject: string;
}

export interface AuthenticateArgs {
  verifier: TokenVerifier;
  /** Raw Node request (for the HTTP `Authorization` header). */
  req?: { headers?: Record<string, string | string[] | undefined> };
  /** Parsed SOAP headers (for `<wsse:Security>`). */
  soapHeaders?: unknown;
}

/**
 * Resolve and verify the caller's OAuth 2.0 access token, trying the HTTP
 * transport first and falling back to the WS-Security message header. The
 * verification itself (signature, issuer, audience, expiry) is identical for
 * both carriers — that is the whole point.
 */
export async function authenticate(args: AuthenticateArgs): Promise<AuthContext> {
  const httpToken = extractHttpBearer(args.req);
  const wsToken = httpToken ? undefined : extractWsSecurityToken(args.soapHeaders);
  const token = httpToken ?? wsToken;

  if (!token) {
    throw new UnauthorizedError(
      'expected an "Authorization: Bearer" header or a <wsse:Security> BinarySecurityToken',
    );
  }

  const claims = await args.verifier.verify(token);
  return {
    claims,
    transport: httpToken ? 'http-bearer' : 'ws-security',
    subject: claims.preferred_username ?? claims.sub ?? claims.azp ?? 'unknown',
  };
}
