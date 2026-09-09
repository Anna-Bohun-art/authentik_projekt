import { InsufficientScopeError } from '../soap/faults.js';
import type { TokenClaims } from './tokens.js';

/**
 * Normalise the granted scopes regardless of whether the IdP used a
 * space-delimited `scope` string (OAuth 2.0 / authentik default) or an `scp`
 * array (Azure AD style).
 */
export function extractScopes(claims: TokenClaims): string[] {
  const raw = claims.scope ?? claims.scp;
  if (Array.isArray(raw)) return raw.filter((s) => typeof s === 'string' && s.length > 0);
  if (typeof raw === 'string') return raw.split(/\s+/).filter(Boolean);
  return [];
}

export function hasScope(claims: TokenClaims, required: string): boolean {
  return extractScopes(claims).includes(required);
}

/** Throws a `insufficient_scope` SOAP fault when the scope is absent. */
export function assertScope(claims: TokenClaims, required: string): void {
  if (!hasScope(claims, required)) {
    throw new InsufficientScopeError(required);
  }
}
