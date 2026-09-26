# OAuth 2.0 – protected SOAP service

A contract-first **SOAP web service** whose every operation is protected by
**OAuth 2.0** access tokens issued by [authentik](https://goauthentik.io/)
(an open-source OIDC Identity Provider). The access token can be presented two
ways — on the HTTP `Authorization` header, or inside a WS-Security
`<wsse:Security>` element in the SOAP envelope — and the service enforces
**per-operation scopes** in both cases.

Built as a focused demonstration of integrating a legacy-style RPC protocol with
a modern token-based authorization stack.

## What it demonstrates

| Area | Where in the code |
|------|-------------------|
| Contract-first **SOAP** (WSDL 1.1 + XSD, document/literal, typed faults, SOAP header) | [`soap-gateway/wsdl/userService.wsdl`](soap-gateway/wsdl/userService.wsdl) |
| **OAuth 2.0** resource server — offline JWT validation against JWKS, `iss` / `aud` / `exp` checks | [`soap-gateway/src/auth/tokens.ts`](soap-gateway/src/auth/tokens.ts) |
| **OIDC** IdP integration (authentik provider, discovery, `client_credentials` grant) | [`docs/authentik-setup.md`](docs/authentik-setup.md), [`client/src/getToken.ts`](client/src/getToken.ts) |
| **Authorization Code + PKCE** — a human logging in through authentik, not a service account | [`web-client/src/index.ts`](web-client/src/index.ts), [`.../oidcClient.ts`](web-client/src/oidcClient.ts), [`.../pkce.ts`](web-client/src/pkce.ts) |
| Fine-grained authorization — **per-operation scopes** (`user.read` / `user.write`) | [`soap-gateway/src/auth/scopes.ts`](soap-gateway/src/auth/scopes.ts), [`.../soap/handlers.ts`](soap-gateway/src/soap/handlers.ts) |
| **WS-Security** — token transported in `BinarySecurityToken` for ESB/legacy interop | [`soap-gateway/src/auth/wsSecurity.ts`](soap-gateway/src/auth/wsSecurity.ts) |
| Middleware / gateway pattern (auth in front of a downstream capability) | [`soap-gateway/src/index.ts`](soap-gateway/src/index.ts) |
| **SQL** — data model + parameterised queries | [`db/10-init-soapdemo.sh`](db/10-init-soapdemo.sh), [`.../directory/postgres.ts`](soap-gateway/src/directory/postgres.ts) |
| **Containerisation** — one-command stack, multi-stage image, healthchecks | [`docker-compose.yml`](docker-compose.yml), [`soap-gateway/Dockerfile`](soap-gateway/Dockerfile) |
| Tests (unit + client↔server integration with an in-test IdP) & **CI** | [`soap-gateway/test/`](soap-gateway/test), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

Architecture and sequence diagrams: [`docs/architecture.md`](docs/architecture.md).

## The service

WSDL at `http://localhost:8000/soap?wsdl`. Namespace `urn:authentik:soap:userservice`.

| Operation | Input | Output | Required scope |
|-----------|-------|--------|----------------|
| `GetUserDisplayName` | `username` | `displayName` | `user.read` |
| `ListGroups` | `username` | `group*` | `user.read` |
| `DeactivateUser` | `username` | `status`, `performedBy` | `user.write` |

Failures come back as SOAP 1.1 `<soap:Fault>` with a stable code in the
`ServiceFault` detail: `unauthorized`, `invalid_token`, `insufficient_scope`,
`not_found`, `bad_request`.

## Quickstart

Prerequisites: Docker + Docker Compose, Node.js ≥ 20.11.

```bash
cd authentik_projekte
cp .env.example .env          # then edit: set strong PG_PASS / AUTHENTIK_* values

docker compose up -d --build  # authentik + postgres + redis + soap-gateway
```

1. Configure the authentik OAuth2 provider once — follow
   [`docs/authentik-setup.md`](docs/authentik-setup.md) (≈5 minutes in the UI).
2. Run the end-to-end demo:

```bash
cd client
cp .env.example .env          # paste CLIENT_SECRET from authentik
npm install
npm run demo
```

The demo obtains a token via `client_credentials`, then calls the service with
the token on the HTTP header, again via WS-Security, and shows a `user.read`
token being refused for `DeactivateUser`.

### Log in as a human instead (Authorization Code + PKCE)

`client/` above is machine-to-machine — no person involved. `web-client/`
adds the flow that does involve one: a real browser redirect to authentik's
login page, then the app calls the SOAP gateway with *your* access token.

```bash
cd web-client
cp .env.example .env    # paste the same CLIENT_SECRET as client/.env
npm install
npm run dev              # then open http://localhost:3000/login
```

One-time setup for this flow (redirect URI + a normal user account, since
`client/`'s setup only covers the service-account grant): step 7 in
[`docs/authentik-setup.md`](docs/authentik-setup.md).

### Run the gateway without Docker

```bash
cd soap-gateway
npm install
cp .env.example .env          # USER_DIRECTORY=memory needs no database
npm run dev
```

## Tests

```bash
cd soap-gateway
npm test          # 26 tests: scope parsing, fault mapping, WS-Security parsing,
                  # + full SOAP client<->server integration over both transports
npm run typecheck
npm run lint
```

The integration suite ([`test/integration/soap.test.ts`](soap-gateway/test/integration/soap.test.ts))
starts a throwaway in-process IdP that serves a JWKS and mints RS256 tokens, so
the real verifier code runs unchanged with no external services.

## Project layout

```
authentik_projekte/
├── docker-compose.yml          authentik (IdP) + postgres + redis + soap-gateway
├── db/10-init-soapdemo.sh      creates the "soapdemo" DB: app_user / app_group / user_group
├── soap-gateway/               the OAuth 2.0 – protected SOAP service (TypeScript)
│   ├── wsdl/userService.wsdl
│   ├── src/
│   │   ├── auth/               tokens (JWKS) · scopes · wsSecurity · authenticate
│   │   ├── soap/               WSDL handlers · Fault mapping
│   │   ├── directory/          UserDirectory: postgres + in-memory impls
│   │   ├── config.ts logger.ts index.ts
│   └── test/
├── client/                     end-to-end demo (client_credentials -> SOAP calls)
├── web-client/                 browser login demo (Authorization Code + PKCE -> SOAP calls)
└── docs/                       architecture + authentik setup
```

## Security

TLS is assumed to terminate in front of the gateway; a bearer token is a
password-equivalent. Audience is pinned, scopes are enforced per operation, and
no secret is baked into an image or the compose file. Full checklist in
[`docs/architecture.md`](docs/architecture.md#security-notes--hardening-checklist).
