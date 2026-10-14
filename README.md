# Cerberus

> Production-grade authentication microservice for backend integrations.

Cerberus is a self-hosted identity provider built with [NestJS](https://nestjs.com),
[Prisma](https://www.prisma.io) and PostgreSQL. It exposes OAuth2 + JWT for
resource servers, an app-bound registration flow for SaaS integrations, and a
separate admin surface for ops + support tooling.

It's designed to be embedded into other products: register users, issue JWTs,
verify them at the gateway, and let admins manage keys / disable MFA / search the
audit log — all without writing your own identity stack.

```text
                          ┌─────────────────────────────────────┐
                          │  Cerberus (single Node process)      │
                          │                                      │
   ┌──────────┐            │   ┌──────────────────────────────┐   │
   │ Acme CRM │────HTTPS──▶│   │ Public listener   (:3000)  │   │
   └──────────┘            │   │  /v1/* + /graphql + /api-docs│   │
                          │   └──────────────────────────────┘   │
                          │   ┌──────────────────────────────┐   │
   ┌──────────┐            │   │ Admin listener   (:3001)  │   │
   │ Operator │──API key──▶│   │  /admin/* + /admin/docs       │   │
   └──────────┘            │   └──────────────────────────────┘   │
                          │                                      │
                          │   ┌──────────────────────────────┐   │
                          │   │ Postgres + Redis (external)   │   │
                          │   └──────────────────────────────┘   │
                          └─────────────────────────────────────┘
```

## Why Cerberus?

- **Dual-listener architecture** — public API and admin API on separate ports
  with independent auth (JWT vs API-key) and independent IP policies.
- **App-bound org resolution** — third-party apps register, get an org, and
  every user who signs up through that app lands in that org. Cross-app session
  replay is blocked at the use-case layer.
- **Domain-Driven Design** with a clean dependency direction: domain layer has
  zero Nest imports. Application layer = use-cases. Infrastructure layer =
  Prisma / Redis / argon2. HTTP / GraphQL live in interfaces/.
- **Stable error codes** — every error returns `{"code": "context.specific.thing",
  "message": "..."}`. Clients branch on `code`, not on HTTP status.
- **Scalar API docs** — interactive OpenAPI 3.1 + bearer-JWT "Authorize" button
  at `/api-docs` (public) and `/admin/docs` (admin).
- **Audit log wired to every state-changing operation** — `identity.user.registered`,
  `authentication.login.succeeded`, `admin.user.mfa_disabled`, etc.

## Quick start

```bash
# 1. Clone + install
git clone https://github.com/Timonics/cerberus.git
cd cerberus
npm ci

# 2. Boot Postgres + Redis + Mailpit (dev SMTP catcher)
npm run infra:up

# 3. Apply migrations + start
cp .env.example .env
npx prisma migrate deploy
npm run start:dev
```

The public listener is now on `http://localhost:3000` and the admin listener
on `http://localhost:3001`. Smoke-test:

```bash
curl http://localhost:3000/health
curl http://localhost:3001/admin/health
# Scalar API docs:
open http://localhost:3000/api-docs
open http://localhost:3001/admin/docs
```

## Architecture

### Bounded contexts

Each context is a `*.module.ts` with `domain/`, `application/`, `infrastructure/`,
and `interfaces/` subdirectories.

| Context | Responsibility |
|---------|----------------|
| `identity` | User registration, profile management, MFA enrollment, password change |
| `authentication` | Login, refresh-token rotation, session management, JWT issuance |
| `authorization` | JWKS, token introspection, signing-key rotation, OAuth2 grants |
| `engagement` | Email verification, password reset, audit log read |
| `administration` | Admin API keys, user override (force-disable MFA), audit search |
| `apps` | Third-party application registration + key rotation |
| `shared` | Domain kernel (errors, events, clock, IDs, persistence port) |

The dependency direction is strict: `domain → (nothing)`, `application → domain`,
`infrastructure → application + domain`, `interfaces → application`. Anything
importing from `@nestjs/*` outside the `interfaces/` and `infrastructure/` layers
is a bug.

### Dual NestApplication

A single Node process runs two `NestFactory.create()` instances:

- **Public** (`AppModule`, port 3000) — every endpoint under `/v1/*` plus `/graphql`
  and `/api-docs`. Open for client apps, web frontends, mobile apps.
- **Admin** (`AdminModule`, port 3001) — every endpoint under `/admin/*` and
  `/admin/docs`. API-key auth + IP allowlist. For ops tooling only.

Both share the same Postgres + Redis instances but have independent DI containers,
independent log streams, and independent crash domains.

### Authentication flow

Cerberus supports two patterns for the public surface:

**Pattern 1: Resource Owner Password Credentials (RFC 6749 §4.3)**

```text
Client                                          Cerberus
  │                                                 │
  ├──POST /v1/auth/login ────────────────────────▶│
  │   { email, password }                          │
  │                                                 │
  ◀── 200 { refreshToken, accessToken } ──────────┤
  │                                                 │
  ├──POST /v1/oauth/token ───────────────────────▶│
  │   grant_type=refresh_token                     │
  │   &refresh_token=...                           │
  │                                                 │
  ◀── 200 { access_token, expires_in } ──────────┤
  │                                                 │
  ├──GET /v1/auth/sessions ─────────────────────▶│
  │   Authorization: Bearer <accessToken>          │
  │                                                 │
  ◀── 200 [ { id, deviceLabel, ... } ] ──────────┤
```

**Pattern 2: App-bound login**

When you register an app, you bind it to a default organization. Users who
register through that app land in that org, and their sessions are scoped to
it — they can't be replayed against a different app's endpoints.

```text
Client                                          Cerberus
  │                                                 │
  ├──POST /v1/identity/register ────────────────▶│
  │   X-Cerberus-App-Id: <app uuid>                │
  │   X-Cerberus-App-Secret: <plaintext key>        │
  │   { email, password }                           │
  │                                                 │
  ◀── 201 { userId, organizationSlug, ... } ───────┤
```

## Configuration

All config is loaded from environment variables. The full set lives in
[`.env.example`](.env.example). The minimum required to boot:

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | `postgresql://cerberus:***@localhost:5434/cerberus` | Postgres DSN. The CI workflow uses port 5432. |
| `REDIS_URL` | `redis://localhost:6384` | For login-attempt counters + rate-limit. |
| `PORT` | `3000` | Public listener. |
| `ADMIN_PORT` | `3001` | Admin listener. |
| `JWT_ISSUER` | `cerberus` | The `iss` claim on every JWT. |
| `JWT_AUDIENCE_DEFAULT` | `cerberus-clients` | The `aud` claim. |
| `ACCESS_TOKEN_TTL` | `900` | Seconds (15 min). |
| `REFRESH_TOKEN_TTL` | `2592000` | Seconds (30 days). |
| `EMAIL_TRANSPORT` | `log` | `log` \| `smtp` \| `sendgrid`. `log` writes to stdout; `smtp` needs the SMTP_* block; `sendgrid` needs `SENDGRID_API_KEY`. |
| `ADMIN_API_KEY_HASH` | empty | Initial value is empty — must be seeded directly via DB on first boot. V1.5 will add a CLI bootstrap command. |
| `ADMIN_IP_ALLOWLIST` | `127.0.0.1/32,::1/128` | CIDR list for the admin listener. |
| `EMAIL_PUBLIC_URL` | `http://localhost:3000` | Used to build email-verification + password-reset links. |

See [`src/config/configuration.ts`](src/config/configuration.ts) for the full
typed shape and [`src/config/env.validation.ts`](src/config/env.validation.ts)
for the Joi schema.

## API surface

### Public listener — port 3000

Every endpoint documented in [`src/openapi.yaml`](src/openapi.yaml).
Interactive: [`http://localhost:3000/api-docs`](http://localhost:3000/api-docs).

| Group | Endpoints |
|-------|-----------|
| Identity | `POST /v1/identity/register`, `PATCH /v1/identity/me`, `POST /v1/identity/change-password`, `POST /v1/identity/mfa/enable`, `POST /v1/identity/mfa/confirm`, `POST /v1/identity/mfa/disable`, `POST /v1/identity/mfa/verify` |
| Auth | `POST /v1/auth/login`, `POST /v1/auth/refresh`, `POST /v1/auth/logout`, `GET /v1/auth/sessions`, `POST /v1/auth/sessions/{id}/revoke` |
| OAuth2 | `POST /v1/oauth/token`, `POST /v1/oauth/introspect`, `POST /v1/oauth/revoke`, `GET /.well-known/jwks.json` |
| Engagement | `POST /v1/engagement/email-verification/{request,confirm}`, `POST /v1/engagement/password-reset/{request,confirm}`, `GET /v1/engagement/audit-log/me` |
| Apps | `POST /v1/apps`, `PATCH /v1/apps/{id}/rotate-key`, `DELETE /v1/apps/{id}` |
| GraphQL | `POST /graphql` (Apollo Sandbox at the same URL) |
| Docs | `GET /api-docs` (Scalar UI) |
| Health | `GET /health` |

GraphQL operations are documented in [`src/graphql/types/*.graphql`](src/graphql/types/).
Both surfaces share the same use-cases — GraphQL is just a second transport.

### Admin listener — port 3001

Every endpoint documented in [`src/openapi-admin.yaml`](src/openapi-admin.yaml).
Interactive: [`http://localhost:3001/admin/docs`](http://localhost:3001/admin/docs).

All `/admin/*` endpoints require:

1. `X-Cerberus-Admin-Api-Key: <key>` header
2. The caller IP is in the `ADMIN_IP_ALLOWLIST` CIDR list

There is **no admin JWT** — operators use the API key directly.

## Integration guide

### 1. Stand up Cerberus

```bash
git clone https://github.com/Timonics/cerberus.git
cd cerberus
npm ci
cp .env.example .env
# Edit .env to point at your Postgres + Redis
npm run infra:up       # only if you want the docker-compose stack
npx prisma migrate deploy
npm run start:prod     # or `npm run start:dev` for hot-reload
```

Verify the public listener:

```bash
curl -sf http://localhost:3000/health
# → {"status":"ok","timestamp":"...","uptime":...}
```

### 2. Register your application

If you're integrating Cerberus into a SaaS product, register an app first. The
app gets its own API key + binds to a default organization. Every user who
signs up through that app lands in that org.

```bash
curl -X POST http://localhost:3000/v1/apps \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Acme CRM",
    "defaultOrgSlug": "acme-org",
    "contactEmail": "ops@acme.com",
    "ttlSeconds": 31536000
  }'
# → 201 { "app": {...}, "apiKey": "..." }
# ↑ STORE THE apiKey IMMEDIATELY. It is shown ONCE.
```

You'll need to seed the `acme-org` first (V1 has no public endpoint for empty
org creation — V1.5 will add `POST /admin/orgs`). The fastest path:

```bash
docker exec cerberus-postgres psql -U cerberus -d cerberus -c \
  "INSERT INTO organizations (id, slug, name, \"createdAt\", \"updatedAt\")
   VALUES (gen_random_uuid(), 'acme-org', 'Acme Corp', NOW(), NOW());"
```

### 3. Register users through your app

```bash
curl -X POST http://localhost:3000/v1/identity/register \
  -H 'Content-Type: application/json' \
  -H 'X-Cerberus-App-Id: <app uuid from step 2>' \
  -H 'X-Cerberus-App-Secret: <plaintext key from step 2>' \
  -d '{
    "email": "alice@acme-customer.com",
    "password": "correct-horse-battery-staple",
    "displayName": "Alice Example"
  }'
# → 201 { userId, organizationSlug: "acme-org", ... }
```

If you skip the `X-Cerberus-App-*` headers, Cerberus falls back to email-domain
matching (if you've populated the `OrganizationDomain` table) or auto-creates a
personal org.

### 4. Authenticate users

```bash
LOGIN=$(curl -s -X POST http://localhost:3000/v1/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Cerberus-App-Id: <app uuid>' \
  -H 'X-Cerberus-App-Secret: <app key>' \
  -d '{"email": "alice@acme-customer.com", "password": "correct-horse-battery-staple"}')

ACCESS_TOKEN=$(echo "$LOGIN" | jq -r .accessToken)
REFRESH_TOKEN=$(echo "$LOGIN" | jq -r .refreshToken)
```

### 5. Call protected endpoints

```bash
curl http://localhost:3000/v1/auth/sessions \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# → 200 [{ id, deviceLabel, ipAddress, expiresAt, ... }]
```

For resource servers in another language, verify the JWT with your JWKS client.
For Node:

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL(`${BASE_URL}/.well-known/jwks.json`));

async function verify(token: string) {
  const { payload, protectedHeader } = await jwtVerify(token, JWKS, {
    issuer: 'cerberus',
    audience: 'cerberus-clients',
  });
  return {
    userId: payload.sub,
    organizationSlug: payload.org ?? null,
    role: payload.role ?? null,
    scopes: (payload.scope as string)?.split(' ').filter(Boolean) ?? [],
  };
}
```

For Python:

```python
import jwt
from jwt import PyJWKClient

jwks = PyJWKClient(f"{BASE_URL}/.well-known/jwks.json")

def verify(token: str) -> dict:
    signing_key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer="cerberus",
        audience="cerberus-clients",
    )
```

### 6. Refresh access tokens

Access tokens expire after 15 minutes. Refresh them via:

```bash
curl -X POST http://localhost:3000/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -H 'X-Cerberus-App-Id: <app uuid>' \
  -H 'X-Cerberus-App-Secret: <app key>' \
  -d "{\"refreshToken\": \"$REFRESH_TOKEN\"}"
# → 200 { accessToken, refreshToken (rotated), ... }
```

The new refresh token replaces the old one. **Reuse detection**: if an attacker
uses the old token, the entire family is mass-revoked. Persist the rotated token
on every refresh.

### 7. Use GraphQL instead of REST

`POST /graphql` accepts the same `Authorization: Bearer <accessToken>`. Apollo
Sandbox is mounted at the same URL. Example introspection:

```graphql
query Me {
  me {
    id
    email
    displayName
    organization { id slug name }
    mfaEnabled
  }
}
```

## Operations

### Postman collection

The repo ships a Postman collection at [`postman/Cerberus.postman_collection.json`](postman/).
It has 45 requests across 16 folders (Identity, Auth, Sessions, OAuth2, Engagement,
Apps, Admin, GraphQL, Examples). The first-run sequence is `Auth → rotate-key →
OAuth/token → Identity/me`. Login scripts auto-save `accessToken` and
`refreshToken` to collection variables.

```bash
npm run postman:generate
# → writes postman/Cerberus.postman_collection.json
# → writes postman/Cerberus.{dev,staging}.postman_environment.json
```

### Database migrations

```bash
# Dev: create a new migration after editing prisma/schema.prisma
npx prisma migrate dev --name <description>

# CI / production: apply pending migrations
npx prisma migrate deploy

# Reset DB (DESTRUCTIVE — dev only)
npx prisma migrate reset
```

### Continuous integration

GitHub Actions runs on every push to `master` and every PR. The workflow at
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs:

1. `npm ci` (audit disabled until transitive vulns are addressed)
2. `npm run build` (TypeScript + copy SDL + copy OpenAPI)
3. Verify generated artifacts
4. `npm run lint` (max-warnings 0)
5. `npx prisma generate`
6. Wait for Postgres healthcheck
7. `npx prisma migrate deploy`
8. Boot `dist/main.js`, hit `/health`, `/.well-known/jwks.json`, `/api-docs`, `/admin/health`, `/admin/docs`
9. Upload `dist/` as a 7-day artifact

### Deployment

`npm run build` then `node dist/main.js`. Both listeners bind in parallel via
`Promise.all([bootstrapPublicApp(), bootstrapAdminApp()])`. No orchestration
needed — it's a single Node process.

For containerized deploys, the docker-compose stack at [`docker-compose.yml`](docker-compose.yml)
is the reference. In production, run Postgres + Redis as managed services and
point `DATABASE_URL` / `REDIS_URL` at them. Set `EMAIL_TRANSPORT=smtp` (or
`sendgrid`) and provide the SMTP_*/SENDGRID_* block.

### Auditing

Every state-changing use-case writes an `identity.*`, `authentication.*`, `apps.*`,
or `admin.*` event to the `audit_logs` table. Stable event-type codes are listed
in [`src/engagement/domain/value-objects/audit-event-type.ts`](src/engagement/domain/value-objects/audit-event-type.ts).
The admin endpoint `GET /admin/audit-log?userId=X&eventType=Y` searches by either
filter (V1 rejects unbounded queries).

## V1.5 limitations and roadmap

Tracked in code as `// V1.5 will add` comments. Highlights:

- **Per-email rate limiting** — login-attempt counters are global, not per-email.
- **Outbox pattern for events** — implemented and live. Use-cases persist
  events to `outbox_events` inside the same transaction; `OutboxRelay`
  polls every 1s and re-publishes through the in-process `EventBus`.
  Crashing between commit and the relay tick now leaves the event
  durably stored rather than dropped. Subscribers (`MailSenderDispatcher`,
  `EngagementAuditLogHandler`) are idempotent so the relay is safe
  to re-publish after a crash. See `src/shared/infrastructure/events/`.
- **Mail-sender subscriber for engagement events** — wired now and
  verified live (Mailpit receives both `engagement.email_verification.requested`
  and `engagement.password_reset.requested` events). `EMAIL_TRANSPORT=sendgrid`
  is configured but hasn't been live-tested against the real SendGrid API.
- **Replace `X-User-Id` placeholder auth** — done in V1.5 (JwtAuthGuard +
  @CurrentUser). The `Authorization: Bearer *** header is required
  for all authenticated endpoints.
- **Cron cleanup of expired rows** — `email_verifications`,
  `password_resets`, expired `mfa_secrets`, and `sessions` are not
  reaped automatically. The tables grow forever until a V1.5
  cron job lands.
- **HTTP hardening** — body limit (100 KiB) + 30s request/response
  timeouts configurable via `HTTP_BODY_LIMIT_BYTES`,
  `HTTP_REQUEST_TIMEOUT_MS`, `HTTP_RESPONSE_TIMEOUT_MS`.
- **`POST /admin/orgs`** — done in V1.5. Operators can pre-create empty
  orgs (`POST /admin/orgs` with `{slug, name, description?}`).
- **Auto-revoke old key on rotation** — done in V1.5. The previous
  `AppApiKey` row is marked `revokedAt = now()` in the same tx as
  the rotation; the new key is the only one that authenticates.
- **Audit log coverage** — done. 23 event types defined in
  `AUDIT_EVENT_TYPES`, all 23 now actually written. Missing ones
  (account lockout, email verified, all 4 engagement events, both
  token events, admin audit searched, admin organization created)
  wired through either in-use-case calls or the
  `EngagementAuditLogHandler` cross-context subscriber.

## Contributing

1. Fork the repo, create a branch off `master`
2. `npm ci` + `cp .env.example .env` + `npm run infra:up`
3. Make your change. Keep the architecture: domain has zero Nest imports.
4. Update the OpenAPI spec + GraphQL SDL + Postman collection for any
   endpoint change.
5. `npm run build` (exit 0), `npm run lint` (0 errors / 0 warnings)
6. Open a PR. The PR template includes a checklist.

## Project layout

```text
src/
├── apps/                    # Public + admin NestApplication bootstraps
├── authentication/          # Login, sessions, refresh tokens
├── authorization/           # JWT, JWKS, OAuth2 grants, signing-key rotation
├── engagement/              # Email verification, password reset, audit log
├── identity/                # User registration, profile, MFA
├── administration/          # Admin keys + audit search + user override
├── apps/                    # Third-party application registration
├── graphql/                 # Schema-first SDLs + resolvers + context
│   ├── types/               # *.graphql SDL files (source of truth)
│   ├── models/              # TS arg/input DTOs for resolvers
│   └── guards/              # GraphQL auth guard
├── shared/                  # Domain kernel + interfaces
├── common/                  # Cross-cutting helpers (artifact-loader, etc.)
├── prisma/                  # PrismaService (singleton)
├── redis/                   # RedisService (login-attempt counter)
├── health/                  # /health + /ready
├── config/                  # ConfigModule + env validation
└── main.ts                  # Boots both apps in parallel

prisma/
├── schema.prisma            # 16 models, 5 enums
└── migrations/              # 5 SQL migrations

postman/                     # Postman collection + 2 env files
docker-compose.yml           # Postgres + Redis + Mailpit for local dev
.github/workflows/ci.yml     # GitHub Actions CI
src/openapi.yaml             # Public OpenAPI 3.1 spec (25 paths)
src/openapi-admin.yaml       # Admin OpenAPI 3.1 spec (6 paths)
```

## License

UNLICENSED — internal project at Timonics. Contact maintainers before
redistributing.
