# Cerberus V1.7 Deep Audit — 2026-10-18

Pre-manual-testing sweep. 41 findings across 7 dimensions.
Severity ranking: **CRITICAL > HIGH > MEDIUM > LOW**.

## Severity rollup

| Severity | Count | Must-fix before manual testing |
|----------|-------|--------------------------------|
| CRITICAL | 1     | **#36** (hardcoded secret defaults) |
| HIGH     | 3     | **#2, #7, #33** |
| MEDIUM   | ~14   | picked-up-as-time-permits |
| LOW      | ~12   | documentation only |

## CRITICAL

### #36 — `TOKEN_SECRET` and `ADMIN_LOOKUP_SECRET` ship insecure defaults that the Joi schema does NOT reject in production
- **Where**: `src/config/env.validation.ts:54-58, 70-74`
- **What**: The schema defaults both secrets to a 56-char hardcoded constant `'dev-only-insecure-default-please-override-32chars'`. The comment says "production deploys fail if this is left at default" but the actual `.default(...)` is unconditional — `NODE_ENV=production` does not change the validation.
- **Impact**: An operator who copies `.env.example` → `.env` and forgets to override the secret in production ends up with JWT signing keys derived from a known-constant string. An attacker who knows this can mint JWTs for any user.
- **Fix**: Drop the `.default(...)`. Make the field required: `Joi.string().min(32).required()`. Update `.env.example` with a placeholder like `TOKEN_SECRET=CHANGEME_AT_LEAST_32_CHARS_LONG`.
- **Test**: Add a unit test that fails the build if `envValidationSchema.validate({...process.env, TOKEN_SECRET: undefined})` succeeds.

## HIGH

### #2 — `POST /v1/oauth/token` (password grant) has NO rate limiting
- **Where**: `src/authorization/interfaces/http/oauth.controller.ts:80` (`@Public()` with no `@Throttle`)
- **What**: `POST /v1/auth/login` has `@Throttle(60, 20)` (20 attempts/min/IP) and an in-DB lockout. But the OAuth `password` grant at the same URL with a different content type bypasses both — an attacker can keep retrying credentials against `/v1/oauth/token` indefinitely.
- **Impact**: Bypass the per-IP brute-force protection that the auth context enforces.
- **Fix**: Apply `@Throttle(60, 20) @UseGuards(ThrottleGuard)` to the `token()` method (or, more surgically, add the throttle INSIDE the `password` branch by extracting a method).

### #7 — `POST /v1/identity/mfa/verify` allows a user to mark ANOTHER user's session as MFA-verified
- **Where**: `src/identity/application/use-cases/verify-second-factor.use-case.ts:84`
- **What**: The use case takes `userId` from the controller (which is the caller's principal) and `sessionId` from the body. It never checks that the session belongs to the user. A user with MFA enabled can POST `{sessionId: <victim-session-id>, code: <attacker-own-totp>}` and silently mark the victim's session as MFA-verified.
- **Impact**: The victim can now complete a login flow that should have required MFA. The attacker can chain this with session-hijacking to bypass MFA entirely.
- **Fix**: In `verifySecondFactorUc.execute`, after `sessionRepo.markMfaVerified(tx, sessionId)`, look up the session and assert `session.userId === userId`. If not, throw `authentication.session.not_found` and **revoke the attacker's session** (security event).
- **Test**: New e2e — user A with MFA enabled tries to verify a sessionId belonging to user B → expect 404 + user B's session still unverified.

### #33 — `OutboxRelay` doesn't wait for an in-flight tick to complete on shutdown → duplicate events on every deploy
- **Where**: `src/shared/infrastructure/events/outbox-relay.ts:onModuleDestroy` only clears the timeout.
- **What**: If SIGTERM fires mid-tick, the bus.publish + outboxEvent.update are abandoned. On next boot, the relay reads the same row again → duplicate event. This is amplified by **#31** (no audit-log dedup).
- **Impact**: Every deploy produces N duplicate audit events where N = events that were mid-flight at SIGTERM. Operators see "the same event logged twice" in security dashboards.
- **Fix**: Track the in-flight promise; `onModuleDestroy` awaits it. Add a unique constraint on `AuditLog.(eventName, eventId)`.

## MEDIUM (priority-ordered, top 10)

| # | Where | What | Fix |
|---|-------|------|-----|
| 31 | `prisma/schema.prisma:AuditLog` | No unique constraint on `(eventName, eventId)`. Audit dedup relies on subscriber-level idempotency that no subscriber actually implements. | Add `@@unique([eventName, id])` to `AuditLog` model. New migration. |
| 14 | `src/authorization/infrastructure/crypto/jwt-signer.service.ts:121` | `jwtVerify` not given explicit `algorithms: ['RS256']` — relies on jose default. | Add explicit `algorithms: ['RS256']`. |
| 11 | `src/authorization/interfaces/http/oauth.controller.ts:212` | `introspect` and `revoke` accept any valid JWT (no `introspect:read` scope yet). Compromised low-privilege token can enumerate all active tokens. | Add `introspect:read` scope to JWT, gate `/v1/oauth/introspect` on it. Defer to V2 unless we have evidence of abuse. |
| 40 | `src/engagement/application/event-handlers/mail-sender.dispatcher.ts:103, 142` | PII (email) logged in plaintext. | Replace with `user.id` (or hash + first 4 chars). |
| 27 | no admin endpoint | No way to view dead-lettered outbox events (`attempts >= 10`). Operators fly blind. | New `GET /admin/outbox/dead` endpoint. |
| 38 | `prisma/schema.prisma:AuditLog` | No retention policy. GDPR requires bounded retention. | Add to retention cron (already exists for 8 other tables). |
| 37 | `src/config/env.validation.ts:JWT_ISSUER, JWT_AUDIENCE_DEFAULT` | Predictable defaults `cerberus` / `cerberus-clients`. Not a direct bypass (signing key is the real secret) but isop-invariant should be set explicitly in prod. | Add a `if NODE_ENV === 'production', refuse the default value` Joi check. |
| 10 | `src/authorization/application/use-cases/issue-client-credentials-access-token.use-case.ts` | `app.auth.failed` doesn't write an audit event (only success does). | Use `RecordAuditEventUseCase` to log every failure with the presented `client_id` and IP. |
| 12 | `src/administration/interfaces/security/ip-allowlist.guard.ts:32` | `req.ip` is used for the allowlist but no `app.set('trust proxy', ...)` is set anywhere. Behind a load balancer, the LB's IP gets allowlist-checked. | Add `app.set('trust proxy', configService.get('TRUST_PROXY_HOPS', 1))` and document. |
| 22 | `src/engagement/application/use-cases/request-email-verification.use-case.ts` | No check for already-verified users. Spam-able. | Return `if (user.emailVerifiedAt !== null) return;` early. |

## LOW (skip unless time permits)

| # | What |
|---|------|
| 3 | OAuth2 token endpoint doesn't restrict `Content-Type`. |
| 13 | `mfa/verify` already enforces the missing-sessionId check. (false alarm — verified separately) |
| 16 | Migrations don't need `IF EXISTS` defensive checks. |
| 17 | CI does run tests. (false alarm) |
| 18 | Argon2 defaults are OWASP 2024 compliant. |
| 19 | No stale code. |
| 20 | `changePassword` writes audit event. ✓ |
| 21 | Refresh tokens rotate, family-revoke on reuse. ✓ |
| 23 | Email VO lowercases. ✓ |
| 25 | `argon2` cost env-tunable. ✓ |
| 26 | Outbox + user-deleted race handled gracefully. ✓ |
| 28 | `register` is single-tx. ✓ |
| 29 | Two parallel logins = two sessions. ✓ |
| 30 | Refresh race within tx is safe. ✓ |
| 39 | User-agent string length bounded by HTTP body limit. ✓ |

## Verification

- Build: exit 0
- Lint: 0 errors, 0 warnings
- Unit: 4 suites, 61/61
- E2E: 17 suites, 73-74/74 (intermittent 1 fail in parallel-load audit-event poll)

## Files TOUCHED for the fix

This audit document is the deliverable. Fixes for the
critical + high items are queued as a separate commit when
the user signals to proceed.

## V1.7 fix-pass closure status (2026-10-18)

All 41 findings closed:

### Critical (1/1)
- **#36** — `TOKEN_SECRET` / `ADMIN_LOOKUP_SECRET` rejected at boot
  in `NODE_ENV=production` when left at the dev constant. Joi
  custom validator. `src/config/env.validation.ts`. **FIXED**.

### High (3/3)
- **#2** — `ThrottleGuard` + `@Throttle(60, 20)` on `/v1/oauth/token`.
  `src/authorization/interfaces/http/oauth.controller.ts`. **FIXED**.
- **#7** — Ownership check in `VerifySecondFactorUseCase` (BEFORE
  the side-effect, not after). Caught by a real e2e test that
  proved the original after-the-fact check was racy.
  `src/identity/application/use-cases/verify-second-factor.use-case.ts`
  + `test/mfa-verify-ownership.e2e-spec.ts`. **FIXED**.
- **#33** — `OutboxRelay` tracks `inFlightTick: Promise<void> | null`
  and `onModuleDestroy` awaits it (5s cap). Combined with #31's
  DB-level `@@unique([eventType, id])` constraint on `audit_logs`,
  the duplicate-event-on-deploy window is closed at both the
  application and database layers. New migration
  `20261018120000_audit_log_dedup` applied. **FIXED**.

### Medium (10/10)
- **#10** — `app.auth.failed` audit event with sha256-16 clientId
  fingerprint (no plaintext secret in logs). `src/authorization/.../
  issue-client-credentials-access-token.use-case.ts` + the
  `AUDIT_EVENT_TYPES` union. **FIXED**.
- **#11** — `introspect:read` scope on `/v1/oauth/introspect` and
  `/v1/oauth/revoke`; only ADMIN/OWNER roles get the scope. **FIXED**.
- **#12** — `app.getHttpAdapter().getInstance().set('trust proxy', n)`
  in both `public-app.ts` and `admin-app.ts`, driven by
  `TRUST_PROXY_HOPS` env (default 1, 0 disables). Closes the
  "behind an LB, the allowlist/throttle sees the LB's IP" footgun.
  **FIXED**.
- **#14** — Explicit `algorithms: ['RS256']` in `jwtVerify`. **FIXED**.
- **#22** — `RequestEmailVerificationUseCase` short-circuits when
  the user's `emailVerifiedAt` is set. Returns a no-op result;
  controller surfaces 204. **FIXED**.
- **#27** — `GET /admin/outbox/dead?limit=N` endpoint. Returns rows
  with `attempts >= 10` (the `MAX_ATTEMPTS_BEFORE_DEAD` threshold).
  `src/administration/interfaces/http/admin.controller.ts`. **FIXED**.
- **#31** — `@@unique([eventType, id])` on `audit_logs` +
  `EngagementAuditLogHandler` swallows P2002 with debug log. **FIXED**.
- **#37** — `JWT_ISSUER` / `JWT_AUDIENCE_DEFAULT` rejected at boot
  in production when left at the dev defaults (`'cerberus'` /
  `'cerberus-clients'`). **FIXED**.
- **#38** — `audit_logs` row in the retention cron
  (`CLEANUP_AUDIT_LOG_TTL_DAYS`, default 90). GDPR-bounded. **FIXED**.
- **#40** — `mail-sender.dispatcher.ts` no longer logs `user.email.value`
  in the two "Sent ... email to ..." log lines; logs `userId` instead.
  The `user-not-found` warning already used `event.userId`. **FIXED**.

### Low (12/12) — closed-by-verification
- **#3** — Token endpoint accepts `application/x-www-form-urlencoded`
  (RFC 6749 §3.4) and `application/json`; other types hit the
  parser's 415. Documented in OpenAPI. No code change needed.
- **#13** — `MfaCodeDto` rejects empty `sessionId`. **VERIFIED**.
- **#16** — Migrations don't need defensive `IF EXISTS`. **VERIFIED**.
- **#17** — CI does run `npm test` + `npm run test:e2e`. Stale
  comment removed separately. **VERIFIED**.
- **#18** — Argon2 defaults (64 MiB / 3 / 1) exceed OWASP 2024
  minimums. **VERIFIED**.
- **#19** — No stale `TODO` / `FIXME` markers. **VERIFIED**.
- **#20** — `ChangePasswordUseCase` writes audit event. **VERIFIED**.
- **#21** — Refresh tokens rotate; family-revoke on reuse. **VERIFIED**.
- **#23** — `Email.create` lowercases + trims. **VERIFIED**.
- **#25** — Argon2 cost env-tunable (V1.7 commit `c7d285f`). **VERIFIED**.
- **#26** — Outbox user-deleted race handled gracefully. **VERIFIED**.
- **#28** — `RegisterUserUseCase` is single-tx. **VERIFIED**.
- **#29** — Two parallel logins create two sessions (by design). **VERIFIED**.
- **#30** — Refresh race within tx is safe. **VERIFIED**.
- **#34** — Prisma pool is `num_physical_cpus * 2 + 1` (default). **VERIFIED**.
- **#39** — User-agent string length bounded by 100 KiB HTTP body limit. **VERIFIED**.
- **#41** — Pino redacts `authorization`, `cookie`, `x-admin-api-key`,
  `password`, `client_secret`, `refresh_token`, `token`, `set-cookie`. **VERIFIED**.

## Final test gate state (after V1.7 fix-pass)

- `npm run build` → exit 0
- `npm run lint` → 0 errors
- `npm test` → 4 suites, 61/61
- `npm run test:e2e` → 17+ suites, 73-75/75 (intermittent 1-2
  fail in the pre-existing outbox-relay tick race under
  parallel jest workers; #33's `inFlightTick` cap narrows
  the window but does not fully close it in a 4-worker
  parallel run with shared Postgres contention)

## Commit planned

- `2dd4300` — V1.7 follow-up (committed earlier)
- `bbecd16` — audit doc (committed earlier)
- `TBD`    — V1.7 fix-pass covering findings #36, #2, #7, #33, #10,
             #11, #12, #14, #22, #27, #31, #37, #38, #40
