import 'dotenv/config';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import * as soap from 'soap';
import { loadConfig } from './config.js';
import { buildAuthorizationUrl, exchangeCodeForTokens, verifyIdToken, type OidcConfig } from './oidcClient.js';
import { createPkcePair, randomState } from './pkce.js';
import {
  consumePendingAuthorization,
  createPendingAuthorization,
  createSession,
  destroySession,
  getSession,
} from './session.js';

/**
 * The user-facing counterpart to client/ (which does client_credentials,
 * machine-to-machine, no human involved). This one runs the Authorization
 * Code + PKCE flow (RFC 6749 §4.1 + RFC 7636) in a real browser, then calls
 * the same SOAP gateway using the *logged-in user's own* access token instead
 * of a service account's. Route map:
 *
 *   GET /          logged-in?   show claims + buttons  :  show a login link
 *   GET /login     start the flow -> redirect to authentik
 *   GET /callback  authentik redirects back here with ?code&state
 *   GET /logout    drop the local session
 *   GET /call/read, /call/write   use the session's access token against soap-gateway
 */
const config = loadConfig();
const oidc: OidcConfig = {
  authorizationEndpoint: config.AUTHORIZATION_ENDPOINT,
  tokenEndpoint: config.TOKEN_ENDPOINT,
  jwksUri: config.JWKS_URI,
  issuer: config.ISSUER,
  clientId: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
  redirectUri: config.REDIRECT_URI,
};

const SESSION_COOKIE = 'sid';

function readCookie(req: IncomingMessage, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return undefined;
}

/** Everything rendered here can contain data that ultimately came from the
 * network (a query param, a claim, a SOAP fault message) — escape it before
 * it goes into HTML so none of it can break out as markup. */
function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;line-height:1.5;padding:0 1rem}
  code{background:#f0f0f0;padding:.1rem .3rem;border-radius:.2rem}
  pre{background:#f5f5f5;padding:1rem;overflow-x:auto;border-radius:.4rem}
  a.button{display:inline-block;background:#1d4ed8;color:#fff;padding:.5rem 1rem;
    border-radius:.4rem;text-decoration:none;margin:.25rem .5rem .25rem 0}
</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

function html(res: ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

function redirect(res: ServerResponse, location: string, headers: Record<string, string> = {}): void {
  res.writeHead(302, { location, ...headers });
  res.end();
}

function handleLogin(_req: IncomingMessage, res: ServerResponse): void {
  const { codeVerifier, codeChallenge } = createPkcePair();
  const state = randomState();
  createPendingAuthorization(state, codeVerifier);
  const url = buildAuthorizationUrl(oidc, { state, codeChallenge, scope: 'openid user.read user.write' });
  redirect(res, url);
}

async function handleCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '', `http://${req.headers.host}`);
  const error = url.searchParams.get('error');
  if (error) {
    html(
      res,
      400,
      layout('Login failed', `<p>authentik returned an error: <code>${escapeHtml(error)}</code></p><p><a href="/">Back</a></p>`),
    );
    return;
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state') ?? undefined;
  const codeVerifier = consumePendingAuthorization(state);
  if (!code || !codeVerifier) {
    html(
      res,
      400,
      layout(
        'Login failed',
        '<p>Missing or expired <code>state</code> — the callback may have been reloaded or replayed. <a href="/login">Try again</a>.</p>',
      ),
    );
    return;
  }

  const tokens = await exchangeCodeForTokens(oidc, { code, codeVerifier });
  const idClaims = tokens.idToken ? await verifyIdToken(oidc, tokens.idToken) : {};

  const sid = createSession({
    accessToken: tokens.accessToken,
    idClaims,
    expiresAt: Date.now() + tokens.expiresIn * 1000,
  });
  redirect(res, '/', { 'set-cookie': `${SESSION_COOKIE}=${sid}; HttpOnly; SameSite=Lax; Path=/` });
}

function handleLogout(req: IncomingMessage, res: ServerResponse): void {
  destroySession(readCookie(req, SESSION_COOKIE));
  redirect(res, '/', { 'set-cookie': `${SESSION_COOKIE}=; Max-Age=0; Path=/` });
}

function handleHome(req: IncomingMessage, res: ServerResponse): void {
  const session = getSession(readCookie(req, SESSION_COOKIE));
  if (!session) {
    html(
      res,
      200,
      layout(
        'SOAP demo — web client',
        '<p>Not logged in.</p><a class="button" href="/login">Log in with authentik</a>',
      ),
    );
    return;
  }
  const who = session.idClaims.preferred_username ?? session.idClaims.sub ?? 'unknown';
  html(
    res,
    200,
    layout(
      'SOAP demo — web client',
      `<p>Logged in as <code>${escapeHtml(who)}</code></p>
       <pre>${escapeHtml(JSON.stringify(session.idClaims, null, 2))}</pre>
       <a class="button" href="/call/read">Call GetUserDisplayName (user.read)</a>
       <a class="button" href="/call/write">Call DeactivateUser (user.write)</a>
       <a class="button" href="/logout">Log out</a>`,
    ),
  );
}

async function handleCall(req: IncomingMessage, res: ServerResponse, kind: 'read' | 'write'): Promise<void> {
  const session = getSession(readCookie(req, SESSION_COOKIE));
  if (!session) {
    redirect(res, '/login');
    return;
  }
  const username = (session.idClaims.preferred_username as string | undefined) ?? 'alice';
  try {
    const client = await soap.createClientAsync(config.GATEWAY_WSDL, { endpoint: config.GATEWAY_ENDPOINT });
    client.setSecurity(new soap.BearerSecurity(session.accessToken));
    const [result] =
      kind === 'read'
        ? await client.GetUserDisplayNameAsync({ username })
        : await client.DeactivateUserAsync({ username });
    html(
      res,
      200,
      layout('SOAP call result', `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre><p><a href="/">Back</a></p>`),
    );
  } catch (err) {
    html(
      res,
      200,
      layout(
        'SOAP call failed',
        `<pre>${escapeHtml((err as Error).message)}</pre>
         <p>Expected if the logged-in user's token does not carry <code>user.write</code>.</p>
         <p><a href="/">Back</a></p>`,
      ),
    );
  }
}

const server = createServer((req, res) => {
  const path = (req.url ?? '/').split('?')[0];
  const dispatch = async (): Promise<void> => {
    switch (path) {
      case '/':
        return handleHome(req, res);
      case '/login':
        return handleLogin(req, res);
      case '/callback':
        return handleCallback(req, res);
      case '/logout':
        return handleLogout(req, res);
      case '/call/read':
        return handleCall(req, res, 'read');
      case '/call/write':
        return handleCall(req, res, 'write');
      default:
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
    }
  };
  dispatch().catch((err: unknown) => {
    console.error(err);
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('internal error');
    }
  });
});

server.listen(config.PORT, () => {
  console.log(`web-client listening on http://localhost:${config.PORT}  — start at /login`);
});
