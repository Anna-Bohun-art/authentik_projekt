import { randomBytes } from 'node:crypto';

/**
 * Two in-memory maps for a single-process local demo:
 *
 *  - `pending`  bridges /login -> /callback: the codeVerifier has to survive
 *    the round trip to authentik and back, keyed by the `state` we sent.
 *  - `sessions` bridges /callback -> later requests: keyed by an opaque id
 *    that only ever leaves this server as an HttpOnly cookie, never the
 *    token itself.
 *
 * A real deployment would put these in Redis (or sign/encrypt them into the
 * cookie) so they survive a restart and work across multiple instances.
 * That is infrastructure, not OAuth, so it is deliberately out of scope here.
 */

export interface Session {
  accessToken: string;
  idClaims: Record<string, unknown>;
  expiresAt: number;
}

const sessions = new Map<string, Session>();

export function createSession(session: Session): string {
  const id = randomBytes(16).toString('base64url');
  sessions.set(id, session);
  return id;
}

export function getSession(id: string | undefined): Session | undefined {
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  if (Date.now() >= session.expiresAt) {
    sessions.delete(id);
    return undefined;
  }
  return session;
}

export function destroySession(id: string | undefined): void {
  if (id) sessions.delete(id);
}

interface PendingAuthorization {
  codeVerifier: string;
  createdAt: number;
}

const pending = new Map<string, PendingAuthorization>();
const PENDING_TTL_MS = 5 * 60 * 1000;

export function createPendingAuthorization(state: string, codeVerifier: string): void {
  pending.set(state, { codeVerifier, createdAt: Date.now() });
}

/** One-time read: a `state` is consumed whether it was found or not, so a
 * replayed /callback can never succeed even if the first attempt failed. */
export function consumePendingAuthorization(state: string | undefined): string | undefined {
  if (!state) return undefined;
  const entry = pending.get(state);
  pending.delete(state);
  if (!entry || Date.now() - entry.createdAt > PENDING_TTL_MS) return undefined;
  return entry.codeVerifier;
}
