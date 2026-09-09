import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { InvalidTokenError } from '../soap/faults.js';

/**
 * Claims we care about on an authentik-issued access token. authentik emits the
 * granted scopes as a space-delimited `scope` string; some providers use an
 * `scp` array instead, so both are accepted downstream (see auth/scopes.ts).
 */
export interface TokenClaims extends JWTPayload {
  scope?: string;
  scp?: string[] | string;
  preferred_username?: string;
  azp?: string;
}

export interface TokenVerifier {
  verify(token: string): Promise<TokenClaims>;
}

export interface VerifierOptions {
  jwksUri: string;
  issuer: string;
  audience: string;
  /** Allow small clock differences between authentik and this service. */
  clockToleranceSeconds?: number;
}

/**
 * Local (offline) JWT validation against the IdP's published JWKS.
 *
 * This is the right default for a resource server: no network round-trip per
 * request, and the JWKS is fetched lazily and cached (with key-rotation
 * handling) by `jose`. If you needed opaque tokens or instant revocation you
 * would swap this implementation for an RFC 7662 token-introspection call.
 */
export function createTokenVerifier(opts: VerifierOptions): TokenVerifier {
  const jwks = createRemoteJWKSet(new URL(opts.jwksUri));

  return {
    async verify(token: string): Promise<TokenClaims> {
      try {
        const { payload } = await jwtVerify(token, jwks, {
          issuer: opts.issuer,
          audience: opts.audience,
          clockTolerance: opts.clockToleranceSeconds ?? 5,
          requiredClaims: ['iss', 'aud', 'exp', 'iat'],
        });
        return payload as TokenClaims;
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'unknown verification error';
        throw new InvalidTokenError(reason);
      }
    },
  };
}
