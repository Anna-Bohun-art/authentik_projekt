import 'dotenv/config';
import * as soap from 'soap';
import { getAccessToken } from './getToken.js';
import { JwtWSSecurity } from './jwtWsSecurity.js';

/**
 * Walks the whole flow end-to-end:
 *   1. get an OAuth 2.0 access token from authentik (client_credentials)
 *   2. call the SOAP service with the token on the HTTP Authorization header
 *   3. call it again with the token inside a WS-Security header
 *   4. show that a read-only token is refused for a write operation
 *
 * Requires the gateway + authentik to be running (docker compose up) and the
 * authentik provider configured per docs/authentik-setup.md.
 */
const cfg = {
  tokenEndpoint:
    process.env.TOKEN_ENDPOINT ?? 'http://localhost:9000/application/o/token/',
  clientId: process.env.CLIENT_ID ?? 'soap-gateway',
  clientSecret: required('CLIENT_SECRET'),
  wsdl: process.env.GATEWAY_WSDL ?? 'http://localhost:8000/soap?wsdl',
  endpoint: process.env.GATEWAY_ENDPOINT ?? 'http://localhost:8000/soap',
};

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing required env var ${name}. Copy .env.example to .env and fill it in.`);
    process.exit(1);
  }
  return value;
}

function heading(text: string): void {
  console.log(`\n=== ${text} ===`);
}

async function main(): Promise<void> {
  heading('1. Obtain access token (OAuth 2.0 client_credentials)');
  const readToken = await getAccessToken({
    tokenEndpoint: cfg.tokenEndpoint,
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    scope: 'user.read',
  });
  console.log(`  got a ${readToken.split('.').length === 3 ? 'JWT' : 'token'} for scope "user.read"`);

  heading('2. GetUserDisplayName  — token on HTTP Authorization header');
  const httpClient = await soap.createClientAsync(cfg.wsdl, { endpoint: cfg.endpoint });
  httpClient.setSecurity(new soap.BearerSecurity(readToken));
  const [displayNameResult] = await httpClient.GetUserDisplayNameAsync({ username: 'alice' });
  console.log('  ->', displayNameResult);

  heading('3. ListGroups  — same token inside a WS-Security <wsse:Security> header');
  const wsClient = await soap.createClientAsync(cfg.wsdl, { endpoint: cfg.endpoint });
  wsClient.setSecurity(new JwtWSSecurity(readToken));
  const [groupsResult] = await wsClient.ListGroupsAsync({ username: 'alice' });
  console.log('  ->', groupsResult);

  heading('4. DeactivateUser with a user.read token  — expected to be refused');
  try {
    await httpClient.DeactivateUserAsync({ username: 'bob' });
    console.log('  !! unexpectedly succeeded');
  } catch (err) {
    console.log('  -> refused as expected:', (err as Error).message.split('\n')[0]);
  }

  heading('5. DeactivateUser with a user.write token');
  try {
    const writeToken = await getAccessToken({
      tokenEndpoint: cfg.tokenEndpoint,
      clientId: cfg.clientId,
      clientSecret: cfg.clientSecret,
      scope: 'user.read user.write',
    });
    const writeClient = await soap.createClientAsync(cfg.wsdl, { endpoint: cfg.endpoint });
    writeClient.setSecurity(new soap.BearerSecurity(writeToken));
    const [deactivateResult] = await writeClient.DeactivateUserAsync({ username: 'bob' });
    console.log('  ->', deactivateResult);
  } catch (err) {
    console.log(
      '  (skipped — the client is probably not granted user.write in authentik):',
      (err as Error).message.split('\n')[0],
    );
  }

  console.log('\nDone.');
}

main().catch((err) => {
  console.error('\nDemo failed:', err);
  process.exit(1);
});
