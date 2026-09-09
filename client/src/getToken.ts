/**
 * OAuth 2.0 Client Credentials grant (RFC 6749 §4.4).
 *
 * This is the machine-to-machine flow: no user is involved, the client proves
 * its own identity with client_id + client_secret and receives an access token
 * scoped to what the IdP has authorised for that client.
 */
export interface TokenRequest {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

export async function getAccessToken(req: TokenRequest): Promise<string> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: req.clientId,
    client_secret: req.clientSecret,
    scope: req.scope,
  });

  const res = await fetch(req.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`token request failed (${res.status}): ${text}`);
  }

  const json = (await res.json()) as TokenResponse;
  return json.access_token;
}
