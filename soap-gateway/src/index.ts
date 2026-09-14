import 'dotenv/config'; // loads .env for local runs; a no-op when there is none (Docker passes env directly)
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import * as soap from 'soap';
import { createTokenVerifier } from './auth/tokens.js';
import { loadConfig } from './config.js';
import { createInMemoryDirectory } from './directory/inMemory.js';
import { createPostgresDirectory } from './directory/postgres.js';
import type { UserDirectory } from './directory/types.js';
import { createLogger } from './logger.js';
import { buildService } from './soap/handlers.js';

const config = loadConfig();
const log = createLogger(config.LOG_LEVEL);

const wsdlPath = fileURLToPath(new URL('../wsdl/userService.wsdl', import.meta.url));
const wsdlXml = readFileSync(wsdlPath, 'utf8');

const verifier = createTokenVerifier({
  jwksUri: config.OIDC_JWKS_URI,
  issuer: config.OIDC_ISSUER,
  audience: config.OIDC_AUDIENCE,
});

let pool: pg.Pool | undefined;
let directory: UserDirectory;
if (config.USER_DIRECTORY === 'postgres') {
  pool = new pg.Pool({
    host: config.PGHOST,
    port: config.PGPORT,
    user: config.PGUSER,
    password: config.PGPASSWORD,
    database: config.PGDATABASE,
  });
  directory = createPostgresDirectory(pool);
} else {
  directory = createInMemoryDirectory();
}

const service = buildService({ verifier, directory, log });

const httpServer = createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  // Anything that is not /soap or the health probe.
  if (!req.url?.startsWith('/soap')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  }
});

const soapServer = soap.listen(httpServer, {
  path: '/soap',
  services: service,
  xml: wsdlXml,
  // Deterministic parsing of the inbound <wsse:Security> header.
  attributesKey: 'attributes',
  valueKey: '$value',
  // Fires once `soap.listen()` has installed its own 'request' listener on
  // httpServer (replacing the base handler above). CORS wrapping has to
  // happen *after* that swap — doing it synchronously right after
  // `soap.listen()` returns races the library's async wsdl.onReady() and
  // ends up wrapping the pre-swap (SOAP-less) listener instead.
  callback: () => {
    if (!config.ENABLE_CORS) return;
    const soapDispatcher = httpServer.listeners('request').slice();
    httpServer.removeAllListeners('request');
    httpServer.addListener('request', (req, res) => {
      if (req.headers.origin) {
        // Reflect the origin (rather than "*") so this still works if a
        // browser ever sends credentials; fine for a local test console,
        // not for prod.
        res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, SOAPAction');
        res.setHeader('Vary', 'Origin');
      }
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }
      for (const listener of soapDispatcher) listener.call(httpServer, req, res);
    });
    log.info('CORS enabled for local testing');
  },
});
soapServer.log = (type, data) => {
  if (type === 'received' || type === 'replied') log.debug({ type }, 'soap traffic');
  else if (type === 'error') log.error({ data }, 'soap server error');
};

httpServer.listen(config.GATEWAY_PORT, () => {
  log.info(
    { port: config.GATEWAY_PORT, directory: config.USER_DIRECTORY, issuer: config.OIDC_ISSUER },
    `soap-gateway listening — WSDL at http://localhost:${config.GATEWAY_PORT}/soap?wsdl`,
  );
});

async function shutdown(signal: string): Promise<void> {
  log.info({ signal }, 'shutting down');
  httpServer.close();
  await pool?.end();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
