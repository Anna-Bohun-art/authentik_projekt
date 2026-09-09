import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import * as soap from 'soap';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTokenVerifier } from '../../src/auth/tokens.js';
import { createInMemoryDirectory } from '../../src/directory/inMemory.js';
import { createLogger } from '../../src/logger.js';
import { buildService } from '../../src/soap/handlers.js';
import { JwtWSSecurity } from '../helpers/jwtWsSecurity.js';
import { startTestIdp, type TestIdp } from '../helpers/testIdp.js';

const wsdlXml = readFileSync(
  fileURLToPath(new URL('../../wsdl/userService.wsdl', import.meta.url)),
  'utf8',
);

let idp: TestIdp;
let httpServer: Server;
let endpoint: string;

beforeAll(async () => {
  idp = await startTestIdp();
  const verifier = createTokenVerifier({
    jwksUri: idp.jwksUri,
    issuer: idp.issuer,
    audience: 'soap-gateway',
  });
  const service = buildService({
    verifier,
    directory: createInMemoryDirectory(),
    log: createLogger('silent'),
  });

  httpServer = createServer((_req, res) => {
    res.writeHead(404);
    res.end();
  });
  soap.listen(httpServer, {
    path: '/soap',
    services: service,
    xml: wsdlXml,
    attributesKey: 'attributes',
    valueKey: '$value',
  });
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  endpoint = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}/soap`;
});

afterAll(async () => {
  httpServer?.close();
  await idp?.close();
});

function createClient(): Promise<soap.Client> {
  return soap.createClientAsync(`${endpoint}?wsdl`, { endpoint });
}

describe('OAuth 2.0 enforcement — HTTP Bearer transport', () => {
  it('rejects an unauthenticated call', async () => {
    const client = await createClient();
    await expect(client.GetUserDisplayNameAsync({ username: 'alice' })).rejects.toThrow(
      /unauthorized/i,
    );
  });

  it('rejects a token minted for a different audience', async () => {
    const client = await createClient();
    client.setSecurity(new soap.BearerSecurity(await idp.issueToken({ audience: 'other-api' })));
    await expect(client.GetUserDisplayNameAsync({ username: 'alice' })).rejects.toThrow(
      /invalid_token/i,
    );
  });

  it('rejects an expired token', async () => {
    const client = await createClient();
    client.setSecurity(new soap.BearerSecurity(await idp.issueToken({ expired: true })));
    await expect(client.GetUserDisplayNameAsync({ username: 'alice' })).rejects.toThrow(
      /invalid_token/i,
    );
  });

  it('accepts a valid user.read token and returns the display name', async () => {
    const client = await createClient();
    client.setSecurity(new soap.BearerSecurity(await idp.issueToken({ scope: 'user.read' })));
    const [result] = await client.GetUserDisplayNameAsync({ username: 'alice' });
    expect(result.displayName).toBe('Alice Anderson');
  });

  it('returns a not_found fault for an unknown user', async () => {
    const client = await createClient();
    client.setSecurity(new soap.BearerSecurity(await idp.issueToken({ scope: 'user.read' })));
    await expect(client.GetUserDisplayNameAsync({ username: 'nobody' })).rejects.toThrow(
      /not_found/i,
    );
  });

  it('enforces per-operation scopes (user.read cannot call DeactivateUser)', async () => {
    const client = await createClient();
    client.setSecurity(new soap.BearerSecurity(await idp.issueToken({ scope: 'user.read' })));
    await expect(client.DeactivateUserAsync({ username: 'bob' })).rejects.toThrow(
      /insufficient_scope/i,
    );
  });

  it('allows DeactivateUser with a user.write token', async () => {
    const client = await createClient();
    client.setSecurity(
      new soap.BearerSecurity(await idp.issueToken({ scope: 'user.read user.write' })),
    );
    const [result] = await client.DeactivateUserAsync({ username: 'bob' });
    expect(result.status).toBe('DEACTIVATED');
    expect(result.performedBy).toBe('svc-demo');
  });
});

describe('OAuth 2.0 enforcement — WS-Security transport', () => {
  it('accepts the same JWT carried in <wsse:Security> BinarySecurityToken', async () => {
    const client = await createClient();
    client.setSecurity(new JwtWSSecurity(await idp.issueToken({ scope: 'user.read' })));
    const [result] = await client.ListGroupsAsync({ username: 'alice' });
    const groups = Array.isArray(result.group) ? result.group : [result.group];
    expect(groups).toContain('engineering');
  });

  it('still rejects an insufficient scope when the token travels in the envelope', async () => {
    const client = await createClient();
    client.setSecurity(new JwtWSSecurity(await idp.issueToken({ scope: 'user.read' })));
    await expect(client.DeactivateUserAsync({ username: 'carol' })).rejects.toThrow(
      /insufficient_scope/i,
    );
  });
});
