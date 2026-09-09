/**
 * Registers this project's OAuth2 provider + application + scopes in a running
 * authentik, using the admin flow API (no manual clicking).
 *
 *   AK_URL=http://localhost:9000 AK_USER=akadmin AK_PASS=... \
 *     tsx scripts/provision-authentik.ts
 *
 * Prints the client_id / client_secret and the issuer / JWKS / token URLs.
 */
const AK = (process.env.AK_URL ?? 'http://localhost:9000').replace(/\/$/, '');
const USER = process.env.AK_USER ?? 'akadmin';
const PASS = process.env.AK_PASS ?? '';
const TOKEN = process.env.AK_TOKEN ?? '';
const CLIENT_ID = 'soap-gateway';
const CLIENT_SECRET = process.env.AK_CLIENT_SECRET ?? 'soap-gateway-demo-secret-0123456789';

if (!PASS && !TOKEN) {
  console.error('set AK_TOKEN (an authentik API token) or AK_PASS');
  process.exit(1);
}

const jar = new Map<string, string>();
function storeCookies(res: Response): void {
  const raw = res.headers.getSetCookie?.() ?? [];
  for (const c of raw) {
    const pair = c.split(';')[0] ?? '';
    const eq = pair.indexOf('=');
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

async function api(path: string, init: RequestInit = {}): Promise<Response> {
  let url = path.startsWith('http') ? path : `${AK}${path}`;
  const method = init.method ?? 'GET';
  for (let hop = 0; hop < 5; hop++) {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(init.headers as Record<string, string>),
    };
    if (TOKEN) headers['Authorization'] = `Bearer ${TOKEN}`;
    const cookies = cookieHeader();
    if (cookies) headers['Cookie'] = cookies;
    if (method !== 'GET') {
      headers['Origin'] = AK;
      headers['Referer'] = `${AK}/`;
      const csrf = jar.get('authentik_csrf');
      if (csrf) headers['X-authentik-CSRF'] = csrf;
      if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(url, { ...init, headers, redirect: 'manual' });
    storeCookies(res);
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      url = new URL(res.headers.get('location')!, url).toString();
      continue;
    }
    return res;
  }
  throw new Error(`too many redirects for ${path}`);
}

async function json<T = any>(res: Response): Promise<T> {
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.url}\n${text}`);
  return text ? JSON.parse(text) : ({} as T);
}

async function login(): Promise<void> {
  const flow = '/api/v3/flows/executor/default-authentication-flow/?query=';
  let challenge = await json(await api(flow));
  for (let i = 0; i < 8; i++) {
    const component: string = challenge.component ?? challenge.type ?? '';
    if (component === 'xak-flow-redirect' || challenge.type === 'redirect') return;
    let payload: Record<string, unknown> | undefined;
    if (component === 'ak-stage-identification') {
      payload = { component, uid_field: USER };
    } else if (component === 'ak-stage-password') {
      payload = { component, password: PASS };
    } else {
      throw new Error(`unexpected auth stage: ${component}\n${JSON.stringify(challenge)}`);
    }
    challenge = await json(
      await api(flow, { method: 'POST', body: JSON.stringify(payload) }),
    );
  }
  throw new Error('login did not converge');
}

async function firstResult<T = any>(path: string): Promise<T | undefined> {
  const data = await json(await api(path));
  return data.results?.[0];
}

async function main(): Promise<void> {
  console.log(`authentik: ${AK}  (auth: ${TOKEN ? 'API token' : `flow login as ${USER}`})`);
  if (!TOKEN) await login();
  const me = await json(await api('/api/v3/core/users/me/'));
  console.log(`logged in as: ${me.user?.username} (superuser=${me.user?.is_superuser})`);

  const authzFlow = await firstResult(
    '/api/v3/flows/instances/?slug=default-provider-authorization-implicit-consent',
  );
  const invalFlow = await firstResult(
    '/api/v3/flows/instances/?slug=default-provider-invalidation-flow',
  );
  const signKey = await firstResult('/api/v3/crypto/certificatekeypairs/?has_key=true&ordering=name');
  if (!authzFlow || !signKey) throw new Error('missing authorization flow or signing key in authentik');
  console.log(`authorization flow: ${authzFlow.slug}`);
  console.log(`signing key: ${signKey.name}`);

  // --- scope mappings -----------------------------------------------------
  async function ensureScope(scopeName: string, desc: string): Promise<string> {
    const existing = await firstResult(
      `/api/v3/propertymappings/provider/scope/?scope_name=${encodeURIComponent(scopeName)}`,
    );
    if (existing) {
      console.log(`scope "${scopeName}" already exists`);
      return existing.pk;
    }
    const created = await json(
      await api('/api/v3/propertymappings/provider/scope/', {
        method: 'POST',
        body: JSON.stringify({
          name: `SOAP ${scopeName}`,
          scope_name: scopeName,
          description: desc,
          expression: 'return {}',
        }),
      }),
    );
    console.log(`scope "${scopeName}" created`);
    return created.pk;
  }
  const scopePks = [
    await ensureScope('user.read', 'Read access to the user-directory SOAP service'),
    await ensureScope('user.write', 'Write access (deactivate users) to the SOAP service'),
  ];
  for (const s of ['openid', 'profile', 'email']) {
    const m = await firstResult(`/api/v3/propertymappings/provider/scope/?scope_name=${s}`);
    if (m) scopePks.push(m.pk);
  }

  // --- OAuth2 provider ---------------------------------------------------
  const provBody = {
    name: 'soap-gateway',
    authorization_flow: authzFlow.pk,
    ...(invalFlow ? { invalidation_flow: invalFlow.pk } : {}),
    client_type: 'confidential',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    signing_key: signKey.pk,
    property_mappings: scopePks,
    sub_mode: 'hashed_user_id',
    issuer_mode: 'per_provider',
    include_claims_in_id_token: true,
    access_token_validity: 'minutes=10',
  };
  let provider = await firstResult('/api/v3/providers/oauth2/?name=soap-gateway');
  if (provider) {
    provider = await json(
      await api(`/api/v3/providers/oauth2/${provider.pk}/`, {
        method: 'PATCH',
        body: JSON.stringify(provBody),
      }),
    );
    console.log('OAuth2 provider "soap-gateway" updated');
  } else {
    provider = await json(
      await api('/api/v3/providers/oauth2/', {
        method: 'POST',
        body: JSON.stringify(provBody),
      }),
    );
    console.log('OAuth2 provider "soap-gateway" created');
  }

  // --- application -----------------------------------------------------
  const appBody = { name: 'SOAP Gateway', slug: 'soap-gateway', provider: provider.pk };
  const app = await firstResult('/api/v3/core/applications/?slug=soap-gateway');
  if (app) {
    await json(
      await api(`/api/v3/core/applications/soap-gateway/`, {
        method: 'PATCH',
        body: JSON.stringify(appBody),
      }),
    );
    console.log('application "soap-gateway" updated');
  } else {
    await json(
      await api('/api/v3/core/applications/', {
        method: 'POST',
        body: JSON.stringify(appBody),
      }),
    );
    console.log('application "soap-gateway" created');
  }

  console.log('\n--- done -------------------------------------------------');
  console.log(`CLIENT_ID       ${CLIENT_ID}`);
  console.log(`CLIENT_SECRET   ${provider.client_secret ?? CLIENT_SECRET}`);
  console.log(`OIDC_ISSUER     ${AK}/application/o/soap-gateway/`);
  console.log(`OIDC_JWKS_URI   ${AK}/application/o/soap-gateway/jwks/`);
  console.log(`TOKEN_ENDPOINT  ${AK}/application/o/token/`);
}

main().catch((err) => {
  console.error('\nPROVISIONING FAILED:\n', err);
  process.exit(1);
});
