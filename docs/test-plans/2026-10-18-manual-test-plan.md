# Cerberus V1.7 Manual Test Plan

Date: 2026-10-18
Codebase: cerberus @ commit `8db4f50`
Stack: NestJS 11 + Prisma 5 + PostgreSQL 16 + Redis 7
Dual-listener architecture: public (`:3000`) + admin (`:3001`)

---

## Pre-test setup

```bash
# 1. Confirm cerberus is up
cd /c/Users/Church/cerberus
docker compose up -d        # postgres + redis + mailpit
cp .env.example .env        # already has dev defaults
npx prisma migrate deploy
npm run build
npm run start:dev
```

## Surfaces to test

### Public (http://localhost:3000)

- Swagger UI: **http://localhost:3000/api-docs**
- Health:    `GET /health` (unauth, returns 200)
- Readiness: `GET /ready`  (unauth, exercises Postgres + Redis)
- JWKS:      `GET /.well-known/jwks.json` (unauth, returns 2048-bit RSA pubkey)

### Admin (http://localhost:3001)

- Admin Swagger: **http://localhost:3001/admin/docs**
- Health:         `GET /admin/health` (unauth, returns 200 with `surface: admin`)
- IP allowlist required for all other admin endpoints: `127.0.0.1/32`,`::1/128` (in `.env`)

---

## Test plan — by group

### 1. Identity lifecycle (no prior user required)

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 1.1 | `POST /v1/identity/register` | Register a user with email + 12+ char password | 201 with `userId` |
| 1.2 | `POST /v1/identity/register` | Re-register same email | 409 `identity.email.in_use` |
| 1.3 | `POST /v1/identity/register` | Password <12 chars | 400 `identity.password.too_weak` |
| 1.4 | `POST /v1/identity/register` | Malformed email | 400 |
| 1.5 | `POST /v1/identity/register` | 11th request from same IP in 1 min | 429 `authentication.rate_limited` |

### 2. Authentication

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 2.1 | `POST /v1/auth/login` | Correct email + password | 200 with `accessToken` + `refreshToken` |
| 2.2 | `POST /v1/auth/login` | Wrong password | 401 `authentication.invalid_credentials` |
| 2.3 | `POST /v1/auth/login` | Unknown email | 401 `authentication.invalid_credentials` (no enumeration) |
| 2.4 | `POST /v1/auth/login` | 21st request in 1 min from same IP | 429 |
| 2.5 | `POST /v1/oauth/token` (`grant_type=password`) | Same login flow as 2.1 | 200 with `access_token` |
| 2.6 | `POST /v1/oauth/token` | 21st request in 1 min from same IP | 429 (V1.7 fix #2) |
| 2.7 | `POST /v1/auth/refresh` | Valid refresh token | 200 with new pair |
| 2.8 | `POST /v1/auth/refresh` | Re-present old refresh token (after rotate) | 401 `authentication.refresh_token_reused` + family mass-revoke |
| 2.9 | `POST /v1/auth/logout` | Valid refresh token | 204, session revoked |
| 2.10 | `GET /v1/auth/sessions` | With Bearer | 200 with session list |
| 2.11 | `POST /v1/auth/sessions/{id}/revoke` | With Bearer | 204, session revoked |

### 3. Email verification

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 3.1 | `POST /v1/engagement/email-verification/request` | With Bearer | 204, mail appears in mailpit (http://localhost:8025) |
| 3.2 | `POST /v1/engagement/email-verification/request` | 2nd call after verified (V1.7 fix #22) | 204, no new mail, no new event |
| 3.3 | `POST /v1/engagement/email-verification/confirm` | With token from mailpit | 204 |
| 3.4 | `POST /v1/engagement/email-verification/confirm` | Bad token | 400 `engagement.email_verification.invalid_token` |

### 4. Password reset

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 4.1 | `POST /v1/engagement/password-reset/request` | With known email | 204 + mail |
| 4.2 | `POST /v1/engagement/password-reset/request` | With unknown email | 204 (no enumeration) |
| 4.3 | `POST /v1/engagement/password-reset/confirm` | With new strong password | 204 |
| 4.4 | `POST /v1/auth/login` | New password | 200 |

### 5. Profile

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 5.1 | `PATCH /v1/identity/me` | Update `displayName` | 200 |
| 5.2 | `POST /v1/identity/change-password` | With old + new | 204, all sessions revoked (force re-login) |

### 6. MFA

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 6.1 | `POST /v1/identity/mfa/enable` | With Bearer | 200 with `secret` (base32) |
| 6.2 | `POST /v1/identity/mfa/confirm` | With TOTP from authenticator app | 204 |
| 6.3 | `POST /v1/auth/login` | User with MFA | 200 with `mfaRequired: true`, NO accessToken |
| 6.4 | `POST /v1/identity/mfa/verify` | With TOTP + own sessionId | 200 with `matched: totp` |
| 6.5 | `POST /v1/identity/mfa/verify` | User A tries to verify User B's sessionId (V1.7 fix #7) | 401 `authentication.session.not_found`, B's session NOT marked |
| 6.6 | `POST /v1/identity/mfa/disable` | With TOTP | 204 |
| 6.7 | `POST /v1/identity/mfa/enable` | 2nd time after confirmed | 409 `identity.mfa.already_enabled` |

### 7. Apps (third-party)

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 7.1 | `POST /v1/apps` (dev mode) | With `name` + `defaultOrgSlug` | 201 with `appId` + `apiKey` (plaintext, ONE TIME) |
| 7.2 | `POST /v1/apps` (NODE_ENV=production) | Without `X-Admin-Token` | 401 |
| 7.3 | `POST /v1/oauth/token` (`grant_type=client_credentials`) | With `client_id` + `client_secret` from 7.1 | 200 with `access_token` |
| 7.4 | `POST /v1/oauth/token` | Bad `client_secret` | 401 `app.auth.failed` + `WWW-Authenticate: Basic` (V1.7 #36/#2) |
| 7.5 | `PATCH /v1/apps/{id}/rotate-key` | With `X-Cerberus-App-Id` + `X-Cerberus-App-Secret` headers | 200 with new `apiKey` |
| 7.6 | `DELETE /v1/apps/{id}` | With same headers | 204, app revoked |
| 7.7 | `POST /v1/oauth/token` (client_credentials) | After revoke | 401 `app.auth.failed` |

### 8. OAuth introspection + revocation

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 8.1 | `POST /v1/oauth/introspect` | With Bearer from an ADMIN/OWNER-scoped token | 200 with `active: true` |
| 8.2 | `POST /v1/oauth/introspect` | MEMBER-scoped token (V1.7 fix #11) | 401 `authorization.scope.required` |
| 8.3 | `POST /v1/oauth/revoke` | With admin Bearer | 200, token revoked |
| 8.4 | `POST /v1/oauth/introspect` | Same token after revoke | 200 with `active: false` |

### 9. Admin (port 3001)

To exercise admin, you need an admin API key. Generate one from inside the cerberus process:

```bash
# Open a separate terminal
cd /c/Users/Church/cerberus
ADMIN_API_KEY=$(npx ts-node -e "..."  # or use the admin-cli if present)
```

Or, simpler: seed one in the database directly via a one-off script. The `IssueAdminApiKeyUseCase` is the entry point; check the e2e test `production-admin-guard.e2e-spec.ts` for a working pattern.

| # | Endpoint | What to verify | Expected |
|---|----------|----------------|----------|
| 9.1 | `POST /admin/api-keys` | With admin key + `name` | 201 with new `apiKey` |
| 9.2 | `GET /admin/api-keys` | With admin key | 200 with list |
| 9.3 | `DELETE /admin/api-keys/{id}` | With admin key | 204, key revoked |
| 9.4 | `POST /admin/orgs` | With `slug` + `name` | 201 with org |
| 9.5 | `POST /admin/orgs` | Same slug again | 409 |
| 9.6 | `GET /admin/users/{id}` | With admin key | 200 with user view |
| 9.7 | `POST /admin/users/{id}/disable-mfa` | With admin key | 204, MFA disabled for that user |
| 9.8 | `GET /admin/audit-log?userId=...` | With admin key | 200 with audit entries |
| 9.9 | `POST /admin/keys/rotate` | With admin key | 200 with new `kid` + `retiredKeyId` |
| 9.10 | `GET /admin/outbox/dead?limit=10` | With admin key | 200 with `{ count, items }` (empty if no dead rows) |

---

## Test plan — audit-finding smokes

Each of the V1.7 fix-pass items has a smoke test:

| Fix | Smoke |
|-----|-------|
| **#2** ThrottleGuard on /v1/oauth/token | Hit /v1/oauth/token 21 times in 1 min → 21st returns 429 |
| **#7** MFA verify ownership | Test 6.5 above |
| **#10** app.auth.failed audit event | After 7.4, `GET /admin/audit-log?userId=<appId>` shows `app.auth.failed` row |
| **#11** introspect:read scope | Test 8.2 above |
| **#12** trust proxy | Check `GET /v1/auth/sessions` from a forwarded client — `req.ip` is the X-Forwarded-For address, not the LB |
| **#14** RS256 only | Send a token with `alg: HS256` → 401 `authorization.token.invalid` |
| **#22** verify no-op for already-verified user | Test 3.2 above |
| **#27** dead outbox endpoint | Test 9.10 above |
| **#31 + #33** audit-log dedup + relay drain | Manually insert a duplicate audit row in postgres; subsequent outbox re-publishes hit the unique constraint, log shows `audit-log dedup: ...` debug line |
| **#36** prod guard on secrets | `NODE_ENV=production npm start` without overriding `TOKEN_SECRET` → exit 1 with the Joi error message |
| **#37** prod guard on JWT_ISSUER | `NODE_ENV=production npm start` without overriding `JWT_ISSUER` → exit 1 |
| **#38** audit_logs retention | Set `CLEANUP_AUDIT_LOG_TTL_DAYS=0` in .env, run `npm run start:dev`, see the retention cron delete no rows. Set to 1, see old rows go. |
| **#40** PII in logs | Tail logs; search for the email of a user who just logged in. Should appear as `userId=...` not `user.email.value=...`. |

---

## What to watch for during manual testing

- **429s during normal use** — if you hit the rate limit while testing, switch to a different email or wait 60s. The throttler key is per-IP + per-email.
- **Mailpit** at http://localhost:8025 — every email the system sends lands here. Useful for verification + password-reset tokens.
- **Prisma Studio** (`npx prisma studio` on port 5555) — browse the database to confirm outbox rows, audit logs, sessions.
- **Admin listener** on port 3001 — to test admin endpoints, your IP must be in `ADMIN_IP_ALLOWLIST` (default `127.0.0.1/32,::1/128`).

## What is NOT in scope for this manual pass

- **GraphQL** — `/v1/graphql` is wired but the manual tests above all use REST. The 4 GraphQL test suites cover the schema; for the REST path, this manual plan is enough.
- **Outbox relay** — observable via `GET /admin/outbox/dead` but the actual relay loop runs every 1s. The `outbox.e2e-spec.ts` covers this.
- **Multi-tenant org-joining flows** — touched indirectly via the `organizationSlug` register param. A multi-tenant E2E would need a test org seeded first.
- **Charon / external consumers** — the client_credentials grant is tested at the Cerberus side. The Charon `CerberusClient` (in charon repo) is out of scope.
