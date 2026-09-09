import { describe, expect, it } from 'vitest';
import { assertScope, extractScopes, hasScope } from '../src/auth/scopes.js';
import { InsufficientScopeError } from '../src/soap/faults.js';

describe('scope extraction', () => {
  it('parses a space-delimited OAuth 2.0 scope string', () => {
    expect(extractScopes({ scope: 'openid user.read user.write' })).toEqual([
      'openid',
      'user.read',
      'user.write',
    ]);
  });

  it('parses an scp array', () => {
    expect(extractScopes({ scp: ['user.read', 'user.write'] })).toEqual([
      'user.read',
      'user.write',
    ]);
  });

  it('returns an empty list when no scopes are present', () => {
    expect(extractScopes({})).toEqual([]);
  });
});

describe('assertScope', () => {
  it('passes when the required scope is granted', () => {
    expect(() => assertScope({ scope: 'user.read' }, 'user.read')).not.toThrow();
  });

  it('throws insufficient_scope when the scope is missing', () => {
    expect(() => assertScope({ scope: 'user.read' }, 'user.write')).toThrow(
      InsufficientScopeError,
    );
  });

  it('hasScope is a non-throwing predicate', () => {
    expect(hasScope({ scope: 'a b' }, 'b')).toBe(true);
    expect(hasScope({ scope: 'a b' }, 'c')).toBe(false);
  });
});
