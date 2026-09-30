import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  consumePendingAuthorization,
  createPendingAuthorization,
  createSession,
  destroySession,
  getSession,
  sweepExpired,
} from '../src/session.js';

const PENDING_TTL_MS = 5 * 60 * 1000;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
});

afterEach(() => {
  // Empty both maps so no test sees another's leftovers.
  sweepExpired(Number.POSITIVE_INFINITY);
  vi.useRealTimers();
});

function newSession(ttlMs = 60_000): string {
  return createSession({ accessToken: 'at', idClaims: { sub: 'u1' }, expiresAt: Date.now() + ttlMs });
}

describe('pending authorization (state -> codeVerifier)', () => {
  it('returns the codeVerifier for a known state', () => {
    createPendingAuthorization('state-1', 'verifier-1');
    expect(consumePendingAuthorization('state-1')).toBe('verifier-1');
  });

  it('is one-time: a replayed state finds nothing', () => {
    createPendingAuthorization('state-1', 'verifier-1');
    consumePendingAuthorization('state-1');
    expect(consumePendingAuthorization('state-1')).toBeUndefined();
  });

  it('rejects an unknown or missing state', () => {
    expect(consumePendingAuthorization('never-issued')).toBeUndefined();
    expect(consumePendingAuthorization(undefined)).toBeUndefined();
  });

  it('rejects a state older than its TTL, and consumes it anyway', () => {
    createPendingAuthorization('state-1', 'verifier-1');
    vi.advanceTimersByTime(PENDING_TTL_MS + 1);
    expect(consumePendingAuthorization('state-1')).toBeUndefined();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    expect(consumePendingAuthorization('state-1')).toBeUndefined();
  });
});

describe('sessions', () => {
  it('issues distinct opaque ids that resolve to their session', () => {
    const a = newSession();
    const b = newSession();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(getSession(a)?.accessToken).toBe('at');
  });

  it('returns nothing for an unknown or missing id', () => {
    expect(getSession('nope')).toBeUndefined();
    expect(getSession(undefined)).toBeUndefined();
  });

  it('is valid until expiresAt and gone from then on', () => {
    const id = newSession(60_000);
    vi.advanceTimersByTime(59_999);
    expect(getSession(id)).toBeDefined();
    vi.advanceTimersByTime(1);
    expect(getSession(id)).toBeUndefined();
    // Deleted on that read, not just hidden: turning the clock back doesn't revive it.
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    expect(getSession(id)).toBeUndefined();
  });

  it('treats a NaN expiresAt as expired, never as "never expires"', () => {
    // `Date.now() >= NaN` is always false; the token response schema keeps
    // NaN out, and this makes the session store fail closed regardless.
    const id = createSession({ accessToken: 'at', idClaims: {}, expiresAt: Number.NaN });
    expect(getSession(id)).toBeUndefined();
    createSession({ accessToken: 'at', idClaims: {}, expiresAt: Number.NaN });
    expect(sweepExpired().sessions).toBe(1);
  });

  it('is gone after logout', () => {
    const id = newSession();
    destroySession(id);
    expect(getSession(id)).toBeUndefined();
  });
});

describe('sweepExpired', () => {
  it('removes only expired sessions and stale pending logins', () => {
    const shortLived = newSession(1_000);
    const longLived = newSession(PENDING_TTL_MS * 2);
    createPendingAuthorization('abandoned', 'v1');

    vi.advanceTimersByTime(PENDING_TTL_MS + 1);
    createPendingAuthorization('fresh', 'v2');

    expect(sweepExpired()).toEqual({ sessions: 1, pending: 1 });
    expect(getSession(shortLived)).toBeUndefined();
    expect(getSession(longLived)).toBeDefined();
    expect(consumePendingAuthorization('fresh')).toBe('v2');
  });
});
