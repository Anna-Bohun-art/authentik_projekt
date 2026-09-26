import { createHash, randomBytes } from 'node:crypto';

/**
 * RFC 7636 (PKCE). Without this, whoever intercepts the authorization `code`
 * on its way back from authentik (e.g. it leaking through browser history, a
 * referrer header, or a malicious app registering the same custom scheme)
 * could redeem it themselves at the token endpoint. PKCE binds the /callback
 * that redeems the code to the same party that started /login: only whoever
 * holds `codeVerifier` can turn `code` into tokens, and `codeVerifier` never
 * leaves this server.
 */
export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

/** RFC 7636 §4.2 — SHA-256 of the verifier, base64url-encoded, no padding. */
export function codeChallengeFromVerifier(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier).digest('base64url');
}

/**
 * §4.1 requires 43-128 characters from [A-Z a-z 0-9 - . _ ~]. 32 random bytes
 * base64url-encode to exactly 43 characters, which is also the minimum —
 * i.e. this is the smallest verifier the spec allows, with full entropy.
 */
export function createPkcePair(): PkcePair {
  const codeVerifier = randomBytes(32).toString('base64url');
  return { codeVerifier, codeChallenge: codeChallengeFromVerifier(codeVerifier) };
}

/** CSRF protection for the redirect (RFC 6749 §10.12): round-tripped through
 * authentik and checked back in /callback before any code is redeemed. */
export function randomState(): string {
  return randomBytes(16).toString('base64url');
}
