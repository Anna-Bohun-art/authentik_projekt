/**
 * Zero-infrastructure live demo.
 *
 *   - starts an in-process OAuth 2.0 / OIDC token issuer (stands in for authentik)
 *   - starts the real soap-gateway on http://localhost:8000
 *   - runs the full flow and prints the actual SOAP request/response XML
 *   - then keeps the server running so you can open the WSDL in a browser
 *
 * Run:  npm run demo:live      (Ctrl+C to stop)
 */
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import * as soap from 'soap';
import { createTokenVerifier } from '../src/auth/tokens.js';
import { createInMemoryDirectory } from '../src/directory/inMemory.js';
import { createLogger } from '../src/logger.js';
import { buildService } from '../src/soap/handlers.js';
import { JwtWSSecurity } from '../test/helpers/jwtWsSecurity.js';
import { startTestIdp } from '../test/helpers/testIdp.js';

const PORT = 8000;
const wsdlXml = readFileSync(
  fileURLToPath(new URL('../wsdl/userService.wsdl', import.meta.url)),
  'utf8',
);

const line = (c = '-') => console.log(c.repeat(74));
const step = (t: string) => {
  console.log('');
  line('=');
  console.log(t);
  line('=');
};

async function main(): Promise<void> {
  const idp = await startTestIdp();
  console.log(`token issuer (mock authentik)  ->  ${idp.issuer}`);

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

  const httpServer = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"status":"ok"}');
      return;
    }
    if (!req.url?.startsWith('/soap')) {
      res.writeHead(404);
      res.end();
    }
  });
  soap.listen(httpServer, {
    path: '/soap',
    services: service,
    xml: wsdlXml,
    attributesKey: 'attributes',
    valueKey: '$value',
  });
  await new Promise<void>((r) => httpServer.listen(PORT, r));
  console.log(`soap-gateway                   ->  http://localhost:${PORT}/soap?wsdl`);

  const endpoint = `http://localhost:${PORT}/soap`;
  const wsdlUrl = `${endpoint}?wsdl`;

  const makeClient = async (label: string) => {
    const client = await soap.createClientAsync(wsdlUrl, { endpoint });
    client.on('request', (xml: string) => {
      console.log(`\n>>> REQUEST (${label})\n${xml}`);
    });
    client.on('response', (body: string) => {
      console.log(`\n<<< RESPONSE\n${body}\n`);
    });
    return client;
  };

  // 1. no token ------------------------------------------------------------
  step('1) Call with NO token  ->  rejected');
  try {
    const anon = await makeClient('no auth');
    await anon.GetUserDisplayNameAsync({ username: 'alice' });
  } catch (err) {
    console.log('result: FAULT -', (err as Error).message.split('\n')[0]);
  }

  // 2. valid token on the HTTP Authorization header ----------------------
  step('2) GetUserDisplayName  ->  token on HTTP  "Authorization: Bearer"');
  const readToken = await idp.issueToken({ scope: 'user.read' });
  const httpClient = await makeClient('HTTP Bearer');
  httpClient.setSecurity(new soap.BearerSecurity(readToken));
  const [displayName] = await httpClient.GetUserDisplayNameAsync({ username: 'alice' });
  console.log('result:', displayName);

  // 3. same token, carried inside the SOAP envelope (WS-Security) --------
  step('3) ListGroups  ->  SAME token inside <wsse:Security> BinarySecurityToken');
  const wsClient = await makeClient('WS-Security');
  wsClient.setSecurity(new JwtWSSecurity(readToken));
  const [groups] = await wsClient.ListGroupsAsync({ username: 'alice' });
  console.log('result:', groups);

  // 4. read-only token cannot do a write op ----------------------------
  step('4) DeactivateUser with a  user.read  token  ->  scope denied');
  try {
    await httpClient.DeactivateUserAsync({ username: 'bob' });
  } catch (err) {
    console.log('result: FAULT -', (err as Error).message.split('\n')[0]);
  }

  // 5. token with user.write succeeds ---------------------------------
  step('5) DeactivateUser with a  user.write  token  ->  allowed');
  const writeClient = await makeClient('HTTP Bearer (user.write)');
  writeClient.setSecurity(
    new soap.BearerSecurity(await idp.issueToken({ scope: 'user.read user.write' })),
  );
  const [deactivated] = await writeClient.DeactivateUserAsync({ username: 'bob' });
  console.log('result:', deactivated);

  step('DEMO COMPLETE — server still running');
  console.log('Open these in your browser:');
  console.log(`  WSDL    http://localhost:${PORT}/soap?wsdl`);
  console.log(`  health  http://localhost:${PORT}/health`);
  console.log('\nPress Ctrl+C to stop.\n');

  const stop = async () => {
    httpServer.close();
    await idp.close();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
