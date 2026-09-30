import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT, type KeyLike } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exchangeCodeForTokens, verifyIdToken, type OidcConfig } from '../src/oidcClient.js';

const KID = 'test-key-1';
let server: Server;
let privateKey: KeyLike;
let cfg: OidcConfig;

/** A throwaway JWKS endpoint, same idea as soap-gateway/test/helpers/testIdp.ts:
 * the real verifyIdToken runs unchanged against it. */
beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };
  server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  cfg = {
    authorizationEndpoint: `http://127.0.0.1:${port}/authorize`,
    tokenEndpoint: `http://127.0.0.1:${port}/token`,
    jwksUri: `http://127.0.0.1:${port}/jwks`,
    issuer: `http://127.0.0.1:${port}/`,
    clientId: 'web-client',
    clientSecret: 'secret',
    redirectUri: 'http://localhost:3000/callback',
  };
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

function idToken(overrides: { aud?: string; iss?: string; sub?: string | null; expired?: boolean } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({ preferred_username: 'alice' })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(overrides.iss ?? cfg.issuer)
    .setAudience(overrides.aud ?? cfg.clientId)
    .setIssuedAt(now)
    .setExpirationTime(overrides.expired ? now - 60 : now + 300);
  if (overrides.sub !== null) jwt.setSubject(overrides.sub ?? 'user-1');
  return jwt.sign(privateKey);
}

describe('verifyIdToken', () => {
  it('accepts a correctly signed token for this client', async () => {
    const claims = await verifyIdToken(cfg, await idToken());
    expect(claims).toMatchObject({ sub: 'user-1', preferred_username: 'alice', aud: 'web-client' });
  });

  it('rejects a token whose aud is another client', async () => {
    await expect(verifyIdToken(cfg, await idToken({ aud: 'soap-gateway' }))).rejects.toThrow(/aud/);
  });

  it('rejects a token from another issuer', async () => {
    await expect(verifyIdToken(cfg, await idToken({ iss: 'https://evil.example/' }))).rejects.toThrow(/iss/);
  });

  it('rejects an expired token', async () => {
    await expect(verifyIdToken(cfg, await idToken({ expired: true }))).rejects.toThrow(/exp/);
  });

  it('rejects a token without sub', async () => {
    await expect(verifyIdToken(cfg, await idToken({ sub: null }))).rejects.toThrow(/sub/);
  });

  it('rejects a token signed by a different key', async () => {
    const other = await generateKeyPair('RS256');
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(cfg.issuer)
      .setAudience(cfg.clientId)
      .setSubject('user-1')
      .setExpirationTime('5m')
      .sign(other.privateKey);
    await expect(verifyIdToken(cfg, forged)).rejects.toThrow(/signature/);
  });

  it('rejects an algorithm other than RS256', async () => {
    const hs = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256', kid: KID })
      .setIssuer(cfg.issuer)
      .setAudience(cfg.clientId)
      .setSubject('user-1')
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode('a-shared-secret-of-at-least-32-bytes!'));
    await expect(verifyIdToken(cfg, hs)).rejects.toThrow(/alg/);
  });
});

describe('exchangeCodeForTokens', () => {
  afterEach(() => vi.unstubAllGlobals());

  function respondWith(body: unknown, status = 200) {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status }));
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  const valid = { access_token: 'at', id_token: 'it', token_type: 'Bearer', expires_in: 600, scope: 'openid' };

  it('sends the code together with its PKCE verifier and maps the response', async () => {
    const fetchMock = respondWith(valid);
    const result = await exchangeCodeForTokens(cfg, { code: 'c1', codeVerifier: 'v1' });
    expect(result).toEqual({ accessToken: 'at', idToken: 'it', expiresIn: 600, scope: 'openid' });

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(cfg.tokenEndpoint);
    const body = new URLSearchParams(String(init.body));
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('c1');
    expect(body.get('code_verifier')).toBe('v1');
    expect(body.get('redirect_uri')).toBe(cfg.redirectUri);
  });

  it('rejects a response without expires_in instead of creating an endless session', async () => {
    const { expires_in: _omitted, ...rest } = valid;
    respondWith(rest);
    await expect(exchangeCodeForTokens(cfg, { code: 'c', codeVerifier: 'v' })).rejects.toThrow(/expires_in/);
  });

  it('rejects a non-numeric expires_in', async () => {
    respondWith({ ...valid, expires_in: '600' });
    await expect(exchangeCodeForTokens(cfg, { code: 'c', codeVerifier: 'v' })).rejects.toThrow(/expires_in/);
  });

  it('rejects a response without access_token', async () => {
    const { access_token: _omitted, ...rest } = valid;
    respondWith(rest);
    await expect(exchangeCodeForTokens(cfg, { code: 'c', codeVerifier: 'v' })).rejects.toThrow(/access_token/);
  });

  it('surfaces an error status from the token endpoint', async () => {
    respondWith({ error: 'invalid_grant' }, 400);
    await expect(exchangeCodeForTokens(cfg, { code: 'c', codeVerifier: 'v' })).rejects.toThrow(/400.*invalid_grant/);
  });
});
