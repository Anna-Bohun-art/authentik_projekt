import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const KID = 'test-key-1';

export interface IssueTokenOptions {
  scope?: string;
  audience?: string;
  issuer?: string;
  subject?: string;
  expiresInSeconds?: number;
  expired?: boolean;
}

export interface TestIdp {
  issuer: string;
  jwksUri: string;
  issueToken(options?: IssueTokenOptions): Promise<string>;
  close(): Promise<void>;
}

/**
 * A throwaway OIDC-ish IdP for tests: it serves a JWKS document and mints
 * RS256 access tokens signed with the matching private key. The gateway's real
 * `createTokenVerifier` runs unchanged against it.
 */
export async function startTestIdp(): Promise<TestIdp> {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  const server: Server = createServer((req, res) => {
    if (req.url?.startsWith('/jwks')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const issuer = `http://127.0.0.1:${port}/`;
  const jwksUri = `http://127.0.0.1:${port}/jwks`;

  return {
    issuer,
    jwksUri,
    async issueToken(options: IssueTokenOptions = {}): Promise<string> {
      const now = Math.floor(Date.now() / 1000);
      const exp = options.expired
        ? now - 60
        : now + (options.expiresInSeconds ?? 300);
      return new SignJWT({
        scope: options.scope ?? 'user.read',
        preferred_username: options.subject ?? 'svc-demo',
      })
        .setProtectedHeader({ alg: 'RS256', kid: KID })
        .setIssuer(options.issuer ?? issuer)
        .setAudience(options.audience ?? 'soap-gateway')
        .setSubject(options.subject ?? 'svc-demo')
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(privateKey);
    },
    close(): Promise<void> {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
