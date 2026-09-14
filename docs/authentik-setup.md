# Configuring authentik as the OAuth 2.0 provider

One-time setup after `docker compose up -d`. Everything here is done in the
authentik admin UI at <http://localhost:9001/if/admin/> (log in as `akadmin`
with the `AUTHENTIK_BOOTSTRAP_PASSWORD` from your `.env`).

## 1. Custom scopes

**Customisation → Property Mappings → Create → Scope Mapping** — create two:

| Name | Scope name | Description |
|------|-----------|-------------|
| `scope-user-read` | `user.read` | Read access to the user-directory SOAP service |
| `scope-user-write` | `user.write` | Write access (deactivate users) |

Leave the *Expression* empty (the scope just needs to exist so it can be
granted and land in the token).

## 2. OAuth2 / OpenID provider

**Applications → Providers → Create → OAuth2/OpenID Provider**

- **Name:** `soap-gateway`
- **Authorization flow:** `default-provider-authorization-implicit-consent`
- **Client type:** `Confidential`
- **Client ID:** `soap-gateway`  ← this is the token `aud`, and must match
  `OIDC_AUDIENCE` in the gateway config
- **Client Secret:** copy it — it goes into `client/.env` as `CLIENT_SECRET`
- **Signing Key:** the default `authentik Self-signed Certificate` (RS256)
- **Scopes:** add `user.read`, `user.write`, plus the default `openid`
- **Subject mode / issuer:** leave defaults. Issuer will be
  `http://localhost:9001/application/o/soap-gateway/` — matches `OIDC_ISSUER`.

## 3. Application

**Applications → Applications → Create**

- **Name:** `SOAP Gateway`
- **Slug:** `soap-gateway`  ← the slug is what makes the discovery URL
  `http://localhost:9001/application/o/soap-gateway/.well-known/openid-configuration`
- **Provider:** `soap-gateway` (the one from step 2)

## 4. Machine-to-machine client (client_credentials)

authentik grants `client_credentials` tokens to a **service account**:

1. **Directory → Users → Create Service account**, name it `svc-soap-demo`.
2. Note it is a member of no groups yet.
3. Back on the **provider**, the `client_credentials` grant works with the
   client ID + secret directly; authentik issues a token whose scopes are the
   intersection of the requested scopes and what the provider allows.
4. To let the client actually request `user.write`, make sure `user.write` is
   in the provider's **Scopes** list (step 2). For a stricter setup, bind the
   application to a policy that only lets certain groups obtain `user.write`.

## 5. Fill in the env files

Repo root `.env` (already created from `.env.example`) needs no change for
authentik itself. Then:

```bash
cp client/.env.example client/.env
# edit client/.env: CLIENT_SECRET=<the secret from step 2>
```

## 6. Smoke test

```bash
# from the host
curl -s -XPOST http://localhost:9001/application/o/token/ \
  -d grant_type=client_credentials \
  -d client_id=soap-gateway \
  -d client_secret=<secret> \
  -d scope=user.read | jq .

# decode the access_token at jwt.io — check: iss, aud=soap-gateway, scope
```

Then run the full demo:

```bash
cd client && npm install && npm run demo
```

## Note on the JWKS URL inside Docker

The demo client (on the host) gets tokens from `http://localhost:9001`, so the
token `iss` is `http://localhost:9001/application/o/soap-gateway/`. The gateway
container cannot reach `localhost:9001`, so `docker-compose.yml` points
`OIDC_JWKS_URI` at `http://host.docker.internal:9001/...` while keeping
`OIDC_ISSUER` as the `localhost` value the token actually carries. If you run
the gateway on the host instead (`cd soap-gateway && npm run dev`), set both to
`localhost` (that is what `soap-gateway/.env.example` does).
