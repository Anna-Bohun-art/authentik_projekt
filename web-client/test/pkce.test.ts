import { describe, expect, it } from 'vitest';
import { codeChallengeFromVerifier, createPkcePair, randomState } from '../src/pkce.js';

describe('codeChallengeFromVerifier', () => {
  it('matches the worked example from RFC 7636 Appendix B', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(codeChallengeFromVerifier(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});

describe('createPkcePair', () => {
  it('derives a challenge that matches its own verifier', () => {
    const pair = createPkcePair();
    expect(codeChallengeFromVerifier(pair.codeVerifier)).toBe(pair.codeChallenge);
  });

  it('generates a verifier within the RFC 7636 length bounds (43-128 chars)', () => {
    const { codeVerifier } = createPkcePair();
    expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(codeVerifier.length).toBeLessThanOrEqual(128);
  });

  it('only uses the unreserved character set the spec requires', () => {
    const { codeVerifier } = createPkcePair();
    expect(codeVerifier).toMatch(/^[A-Za-z0-9._~-]+$/);
  });

  it('never repeats across calls', () => {
    const a = createPkcePair();
    const b = createPkcePair();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });
});

describe('randomState', () => {
  it('produces a non-empty, URL-safe token', () => {
    const state = randomState();
    expect(state.length).toBeGreaterThan(0);
    expect(state).toMatch(/^[A-Za-z0-9._~-]+$/);
  });

  it('never repeats across calls', () => {
    expect(randomState()).not.toBe(randomState());
  });
});
