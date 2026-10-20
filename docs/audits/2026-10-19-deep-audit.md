# Cerberus Deep Audit — 2026-10-19

Second full-repo sweep (prior: 2026-10-18-deep-audit.md). Seven dimensions audited
in parallel: config/crypto, authentication/sessions, authorization/tenant isolation,
identity/MFA/engagement, GraphQL & input validation, infra/logging/reliability,
data model & tests. Prior audit's 41 closures were re-verified in code; most are
genuinely fixed (listed per-dimension below). This report covers **new** findings.

Severity ranking: **CRITICAL > HIGH > MEDIUM > LOW**.

## Severity rollup

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 12 |
| MEDIUM | ~20 |
| LOW | ~15 |

## Verified prior fixes (spot-checked in code, not just claimed)

- **#36/#37** prod rejects default `TOKEN_SECRET`/`ADMIN_LOOKUP_SECRET`/issuer — `src/config/env.validation.ts:34-132` (but see H-4)
- **#2** `@Throttle(60,20)` on `/v1/oauth/token` — `oauth.controller.ts:100-101`
- **#7** MFA-verify ownership check before side-effect — `verify-second-factor.use-case.ts:100-109,146-155`
- **#11** `introspect:read` scope on introspect/revoke — `oauth.controller.ts:237-261`
- **#12** trust proxy wired both listeners — `src/apps/public-app.ts:56-59`, `admin-app.ts:56-59` (but see H-11)
- **#14** `algorithms: ['RS256']` pinned — `jwt-signer.service.ts:128-132`
- **#22** email-verification short-circuit for verified users — `request-email-verification.use-case.ts:76-84`
- **#27** `GET /admin/outbox/dead` — `admin.controller.ts:175-211`
- **#33** outbox relay awaits in-flight tick on destroy — `outbox-relay.ts:60,81-94`
- **#38** audit_logs retention (90d) — `prisma-cleanup.repository.ts:152-160`
- **#40** mail dispatcher logs userId, not email — `mail-sender.dispatcher.ts:103,142`
- Argon2id everywhere (passwords, app keys, admin keys, recovery codes), 256-bit CSPRNG
  tokens, HMAC-keyed stored hashes for reset/verification tokens, atomic refresh
  compare-and-swap (`prisma-session.repository.ts:127-141`), constant-time dummy-hash
  login, password-reset timing equalization on unknown email, single-use in-tx token
  consumption, global `ValidationPipe` whitelist+forbidNonWhitelisted, no raw SQL
  outside a literal `SELECT 1`, CORS `origin: false` both listeners, body limit +
  timeouts wired, non-root Dockerfile, fail-closed empty allowlist.

## CRITICAL

### C1 — MFA fully bypassable via `POST /v1/auth/refresh`
- **Where**: `src/authentication/interfaces/http/auth.controller.ts:115-139` → `refresh-session.use-case.ts:91-249`
- **What**: The OAuth2 `refresh_token` grant checks `session.mfaVerified` (`refresh-token-grant.use-case.ts:94-100`); the parallel REST refresh path never does — it checks only `isAliveAt()`. `login.use-case.ts:358-366` returns a **usable plaintext refreshToken even when `mfaRequired: true`** (session persisted with `mfaVerified=false`).
- **Attack**: attacker with only the victim's password → `POST /v1/auth/login` → `{ mfaRequired: true, refreshToken }` → `POST /v1/auth/refresh` → full-scope access-token JWT. The entire second factor is defeated by one extra request. *Fix note: the hole is load-bearing — `/v1/identity/mfa/verify` is JWT-gated while MFA login issues no JWT, so closing it requires issuing a scoped "MFA-pending" token at login (or accepting session-id + refresh-token proof at `mfa/verify`).*
- **Fix**: reject refresh when `!existing.mfaVerified` (mirror the OAuth grant) **and** make `mfa/verify` reachable in the pending state via a limited token.

### C2 — Unauthenticated GraphQL `rotateAppKey` mints a plaintext API key for ANY app
- **Where**: `src/apps/interfaces/graphql/apps.resolver.ts:64-91`
- **What**: `@Public()` is REST metadata — a no-op in GraphQL (no global guard exists). `rotateAppKey` and `revokeApp` have no credential check; `RotateAppApiKeyUseCase.execute` trusts the caller and returns the new plaintext key. The V1.5 REST hardening (`requireOwnCurrentKey`, `apps.controller.ts:60-82`) was never mirrored.
- **Attack**: any internet caller with an app UUID (they leak in audit payloads, GraphQL responses, logs) → `mutation { rotateAppKey(id: "...") { apiKey } }` → full app impersonation **and** the legitimate key is revoked. `revokeApp` gives unauthenticated DoS against any app. `test/apps-graphql.e2e-spec.ts` codifies the unauthenticated happy path.
- **Fix**: require app credentials (or the production admin guard) on both mutations; add an e2e invariant test that every Mutation is auth-gated or justified.

### C3 — Plaintext password-reset / email-verification tokens persisted in `outbox_events.payload`
- **Where**: `src/shared/infrastructure/events/prisma-outbox.repository.ts:86-108`, `src/engagement/domain/events/engagement.events.ts:31,77`
- **What**: `serialize()` copies every public field into the DB row, including `plaintextToken` — despite the `MailSenderDispatcher` docstring claiming it is "never persisted". Rows retained 7 days (`CLEANUP_OUTBOX_TTL_DAYS`); dead-lettered rows (`attempts >= 10`) are never deleted; a crash before `processedAt` re-sends the still-valid link.
- **Impact**: the engagement tables deliberately store only *hashed* tokens, but the outbox row next to them holds the live token in JSON — any DB backup/replica reader/SQLi → account takeover via `/v1/engagement/password-reset/confirm`.
- **Fix**: strip `plaintextToken` in `serialize()` (pass out-of-band to the dispatcher only); add cleanup for dead-lettered rows older than token TTL.

## HIGH

### H-1 — GraphQL `registerApp` bypasses the `ProductionAdminGuard`
- `apps.resolver.ts:34-59` exposes `registerApp` unauthenticated while REST requires an admin key in production (`apps.controller.ts:84-86`). In production anyone can mint app credentials over `/graphql`. Chain with H-3 and C2 for a fully unauthenticated takeover path.

### H-2 — Cross-tenant reads via GraphQL `org:admin` scope
- `getUser`/`adminUser` (`identity.resolver.ts:89-109`, `admin.resolver.ts:49-64`) and `adminAuditLog` (`admin.resolver.ts:97-131`) require only `org:admin` (any org OWNER/ADMIN) but perform **no org-boundary check** — unlike `adminDisableUserMfa`, which has one (`admin-disable-user-mfa.use-case.ts:122-145`). Any org admin reads any tenant's users (email, role, MFA status) and up to 500 audit entries (IPs, user agents, payloads). The global REST search is acceptable behind the IP allowlist + admin key; the GraphQL mirror sits on the public listener.

### H-3 — App `allowedScopes` is caller-controlled; app JWTs accepted as user principals
- `apps.dto.ts:55-58` takes `initialScopes` as free text → persisted verbatim (`register-app.use-case.ts:86`) → self-granted via `client_credentials` (`issue-client-credentials-access-token.use-case.ts:208-214`). Neither `JwtAuthGuard` (`jwt-auth.guard.ts:120-133`) nor `VerifyAccessTokenUseCase` checks the `typ` claim, so an app JWT (`sub = appId`) with `scope: "org:admin"` passes `requireOrgAdmin` — re-opening H-2 with no user account. Chained with H-1/C2 this is unauthenticated.

### H-4 — Production secret-default rejection is void when `NODE_ENV` comes from `.env`
- `env.validation.ts:39,62,78,119` read `process.env['NODE_ENV']` directly, but `@nestjs/config` loads env-file values into the validation input object, **not** into `process.env` (assignVariablesToProcess runs after validation). The standard Docker-`env_file`/dotenv pattern (`NODE_ENV=production` only in `.env`) boots with `process.env.NODE_ENV === undefined` → the #36 CRITICAL fix never fires → production runs with the world-known `TOKEN_SECRET`.
- **Fix**: `Joi.string().when('NODE_ENV', {...})` against the validated value, not the raw environment.

### H-5 — Second-factor and TOTP material gaps
- **H-5a TOTP secrets plaintext at rest**: `MfaSecret.secret` stored plaintext (`prisma/schema.prisma:161-165`) — a DB dump yields every user's live TOTP key (recovery codes, lower-value, are argon2-hashed). Encrypt with a boot-required master key.
- **H-5b `mfa/verify` unthrottled, un-audited**: no throttle, no failure counter, no lockout, no audit event (`identity.controller.ts:171-184`, `verify-second-factor.use-case.ts:126-129`). An attacker holding a pre-MFA credential (the exact threat MFA exists for) gets unlimited online guesses at a 10⁶ space with zero logging.

### H-6 — GraphQL has zero rate limiting — every REST brute-force/spam control is transport-bypassable
- No global guard, no `ThrottleGuard` on any resolver; `ThrottleGuard` is HTTP-route-scoped (`throttle.guard.ts:111`). Consequences: `requestPasswordReset` via `/graphql` is unthrottled (email-bombing + SMTP/SendGrid quota burn — REST caps it at 5/min *specifically* to prevent this); `register` via GraphQL bypasses its throttle → argon2id CPU-exhaustion DoS; `confirmPasswordReset` token guessing unthrottled.

### H-7 — Refresh-token reuse detection is dead code; legit double-refresh mass-revokes
- `refresh-session.use-case.ts:148-184`: the "second lookup" promised in the comment doesn't exist; `findByRefreshHash` matches only the current unique column, so a stolen *old* token returns 401 with **no family revocation and no detection** — the only revocation that fires is the false-positive: two concurrent refreshes with the same valid token → loser's compare-and-swap matches 0 rows → `FAMILY_COMPROMISED` mass-revoke (`:204-225`). Legitimate client retries (timeout, two tabs) force-log the user out. Also: `revokeAllInFamily` emits no audit row or event — a genuine compromise revocation is invisible.
- Prior audit item **#30 ("refresh race within tx is safe — VERIFIED") is refuted** and should be re-opened.

### H-8 — Unauthenticated, targeted, indefinitely repeatable account-lockout DoS
- `login.use-case.ts:220-240` + `lockout-policy.ts:27`: 5 failed attempts per `(email, ip)` → victim's credential row locked 15 min for **all** login paths. 5 requests suffice and re-locking every 15 min keeps the account frozen forever. No CAPTCHA, no notification. Amplified because the OAuth password grant passes no IP (`oauth.controller.ts:124-128` → lockout key collapses to `email:0.0.0.0`, splitting counters and destroying per-IP forensics) and `ThrottleGuard.extractEmail` only reads `body.email`, never `body.username` (`throttle.guard.ts:174`) — the per-email bucket never fires on `/v1/oauth/token`.

### H-9 — Pino redaction misses the actual secret field names
- `app-logger.module.ts:52-61` redacts `req.body.password`, `client_secret`, `refresh_token`, `token` — but the real DTOs use `code` (TOTP + 10-char recovery codes, `mfa-code.dto.ts:24`) and `currentPassword`/`newPassword` (`change-password.dto.ts:6,10`). Every MFA verify/confirm and every password change writes live secrets to the log stream.

### H-10 — Prior audit's audit-dedup fix (#31) is tautological — duplicates still persist
- `prisma/schema.prisma:364` `@@unique([eventType, id])` — but `id` is the row's own PK and `record-audit-event.use-case.ts:43` generates a **fresh UUID per insert**. Re-published events still insert new rows; the P2002 catch in `engagement-audit-log.handler.ts:94` is dead code. The prescribed constraint was `@@unique([eventName, eventId])`. Every deploy/re-publish still duplicates security-audit events. No test asserts dedup — which is why it slipped.

### H-11 — Admin listener trusts `X-Forwarded-For` by default
- `TRUST_PROXY_HOPS` defaults to 1 (`configuration.ts:302`) including on the **admin** app (`admin-app.ts:56-59`). If port 3001 is directly reachable (the docker-compose topology implies exactly that), any client sets `X-Forwarded-For: 127.0.0.1` and walks past the IP allowlist; the API key is the sole remaining control. Needs `TRUST_PROXY_HOPS=0` semantics per-listener or a boot check. (This is the #12 fix's footgun.)

### H-12 — `mfa_required` login response is a password-validation oracle
- `oauth.controller.ts:134-142`: correct password + MFA → 403 `mfa_required` + live `session_id`; wrong password → 401. Every correct guess is positively signalled and hands out a session id. Return the same 401 shape.

## MEDIUM (grouped)

**AuthZ / tokens**
- `IssueAccessTokenUseCase` silently no-ops when the pinned org slug doesn't exist → token minted scoped to the user's *first* org instead of failing (`issue-access-token.use-case.ts:124-129`).
- TOTP codes replayable within their validity window; no used-step tracking (`totp.service.ts:53-54` claim is false; RFC 6238 §5.2 requires it). Also affects `mfa/disable`'s "fresh code" claim.
- TOTP window actually 0, not the documented ±1 (`totp.service.ts:16-18` vs compiled otplib default) — stricter than docs, UX defect.
- Recovery-code path distinguishes "wrong" vs "used" by message text (`verify-second-factor.use-case.ts:173-182`).
- Enabling MFA requires only a bearer token (no fresh auth) and does **not** revoke existing sessions/tokens (`confirm-mfa` has no `PasswordChanged`-style revoker) — token theft converts to persistent MFA lockout; a user enabling MFA after suspected compromise leaves attacker sessions alive 30 days.

**Engagement**
- Password-reset confirm bypasses the password policy (no `Password.create`; GraphQL input has no length bound at all — `graphql/models/inputs.ts:55-58`) and writes **no audit event** for the credential rotation (`confirm-password-reset.use-case.ts:60-103`).
- Email-domain org auto-join grants membership at registration before email ownership is verified (`register-user.use-case.ts:300-316`) → `attacker@acme.com` gets org-scoped JWTs with no proof.
- Plaintext email persisted in `audit_logs` on every failed login (`login.use-case.ts:379-384`), retained 90 days — the project's own #40 bar applied to mail logs only.
- `EMAIL_TRANSPORT=log` (default) writes live reset/verification URLs incl. `?token=` to stdout; not production-rejected (`log-mail-sender.ts:19-21`).
- Email templates interpolate unescaped `displayName` and URL into HTML (`email-templates.ts:40,82`) — latent stored-HTML injection if templates are ever reused for third-party recipients.

**GraphQL / API correctness**
- Introspection **and** Playground default to ON in production with no NODE_ENV gate (`configuration.ts:332-335`).
- No depth/alias/batch limits — N aliased `getUser` calls = N sequential Prisma round-trips per request (`graphql.module.ts:50-55`).
- `Authorization.verifyAccessToken` resolver fabricates claims: hardcoded `iss: 'cerberus'`, `aud: 'cerberus-clients'`, `exp = now+900` regardless of the real token (`authorization.resolver.ts:44-48`) — misleads any resource server that consumes it.
- Admin audit search: `offset` validated then silently dropped (repo has no `skip` — `admin-search-audit-log.use-case.ts:111-134`); invalid `from`/`to` dates → 500 not 400 (`admin.controller.ts:127-128`); caller never recorded in the `admin.audit.searched` row (`callerUserId: null`).
- GraphQL `adminDisableUserMfa` accepts caller-forged `adminKeyId` written into the audit payload (`admin.resolver.ts:74-84`).

**Infra / reliability**
- `uncaughtException`/`unhandledRejection` handlers log and continue (`main.ts:34-39`) — Node/Nest guidance is terminate + restart; a corrupted auth process keeps serving.
- Expired-but-never-revoked sessions never purged (cleanup deletes only `revokedAt < now-TTL`); `sessions` has no index on `revokedAt`/`expiresAt` → full-table scans on the largest hot table every cron pass (`prisma-cleanup.repository.ts:42-83`). Same unindexed-`expiresAt` pattern on `email_verifications`/`password_resets`/`invitations`.
- `Session.organizationId` has no FK and a `@db.Uuid` type mismatch with TEXT `organizations.id` — org scoping never DB-validated (`schema.prisma:245`); `signing_keys.isCurrent` uniqueness is app-layer only (two concurrent rotations → two "current" keys).
- Unbounded single-statement `deleteMany` for 90 days of audit_logs (row locks + bloat under load).
- `/ready` leaks raw Prisma error strings unauthenticated (`postgres.indicator.ts:34-38`).
- helmet skipped entirely (not just CSP) on the docs paths (`public-app.ts:90-100`, `admin-app.ts:79-91`).
- docker-compose publishes Postgres (default password `cerberus`) and unauthenticated Redis on `0.0.0.0` (`docker-compose.yml:20-21,38-39`).

**Dependencies**
- `npm audit` could not be run in this sweep (denied). CI sets `NPM_CONFIG_AUDIT: false` with a comment admitting "10 known transitive vulns (axios, graphql, and others)" (`.github/workflows/ci.yml:105-108`) — a standing, self-admitted unpatched backlog. `jose` is locked at 5.10.0 and will never reach current 6.x under `^5.9.6`. **Action: run and triage `npm audit` before shipping.**

## LOW (selection)

- `/v1/auth/refresh`, `/v1/auth/logout` unthrottled; `/v1/auth/sessions/:sessionId/revoke` ignores its path param (revokes `body.sessionId`).
- `Math.random()` for Redis sorted-set member token (`redis-login-attempt.repository.ts:99-107`) — contradicts the file's CSPRNG posture.
- Registration leaks account existence (`identity.email.taken` → 409) and app-id existence/state (distinct 404/401/403 codes) — throttled but real oracles.
- Partial `X-Cerberus-App-*` headers silently ignored at registration → user bound to wrong org instead of rejected (`identity.controller.ts:78`).
- Concurrent same-email registration → raw 500 (no P2002 handler in `register-user.use-case.ts:160-223`; repo comment is false).
- `legacySha256` dead code; divergent second dev-default string in `configuration.ts:249`; `.env.example` omits `TOKEN_SECRET`/`ADMIN_LOOKUP_SECRET`.
- Admin key revocation has no hierarchy check — a leaked CI key can revoke the operator's last key (last-key lockout, needs DB recovery).
- Lenient IPv4 octet parsing: `10.0..5/32` parses as `10.0.0.5` instead of being rejected (`ip-allowlist.guard.ts:140-150`).
- JWT verify-key cache never re-checks key expiry (`jwt-signer.service.ts:113-117`); `ACCESS_TOKEN_TTL` has no Joi max.
- Orphan-prone engagement tables lack FKs to `users`; redundant indexes on `AdminApiKey`; no `@@unique([organizationId, email])` on `Invitation`.
- `verify-app-api-key` runs argon2 verify before the expiry check (CPU cost on expired keys).

## Test & coverage assessment

- Unit: **4 suites, 61/61 pass** (verified by running `npx jest` this sweep). Only `throttle.guard`, `ip-allowlist.guard`, `engagement-audit-log.handler`, `session` aggregate have unit tests.
- **No unit tests for**: login use case, refresh rotation/reuse detection, jwt-signer, verify-second-factor ownership, admin API-key verification, env-validation production rejection (the #36 fix's own prescribed test), outbox relay, cleanup repository.
- **No e2e for**: account lockout behavior, refresh-token reuse → family revoke (only rotation atomicity is pinned), IP-allowlist 403 from a non-allowed IP, admin API-key negative auth, and — critically — **no test asserts audit-log dedup on relay re-publish** (H-10 slipped because of exactly this).
- `coverageThreshold` in `package.json:115-121` is lines:8/branches:5 — effectively zero; it would pass if 90% of auth-critical code were deleted untested.
- E2E that *does* exist is genuinely good: MFA ownership, cross-tenant IDOR, atomic refresh, rate limiting, client_credentials scopes, outbox, cleanup, admin lifecycle, GraphQL resolvers — but `test/apps-graphql.e2e-spec.ts` codifies the C2 unauthenticated happy path instead of catching it.

## Dominant systemic pattern

Every CRITICAL and most HIGHs share one root cause: **security controls are applied per-transport, and GraphQL is systematically the weaker transport.** The apps key-rotation credential check, the production registration guard, the entire throttle layer, and several org-boundary checks exist on REST only; GraphQL resolvers call the same use-cases and inherit none of it, and `@Public()` on GraphQL methods is decorative. Second pattern: **prior-audit closures were verified at the REST layer and gave false confidence about parallel paths** (MFA check fixed in the OAuth grant but not REST refresh; dedup constraint added but tautological; trust-proxy fix created the admin XFF footgun).

**Recommended first moves**: C1 + C2 + C3 fixes, a global GraphQL guard/throttle strategy, a server-side app-scope registry + `typ` claim check, and an e2e invariant that every SDL Mutation is auth-gated or carries a written justification.


---

# V1.8 fix-pass closure status (2026-10-20)

All findings in this audit were fixed in a five-workstream implementation pass plus an
integration phase (schema reconciliation, 8 new migrations, full e2e-suite update, docs
sync, dependency triage). **106 files changed, +4,062/−1,135 lines.** Nothing committed
— the working tree is the deliverable.

## Verification (final state)

| Check | Result |
|-------|--------|
| `npm run build` | green |
| `npm run lint` (--max-warnings 0) | 0 errors, 0 warnings |
| Unit tests | 67/67 (incl. new ip-allowlist, mfa-attempt, outbox-cipher, session-grace suites) |
| E2E (`test/jest-e2e.json --maxWorkers=2`) | **23/23 suites, 112/112 tests** |
| `npx prisma migrate deploy` | 20 migrations, in sync |
| Postman collection | regenerated (login/MFA-pending contract, mfa/verify token capture) |

## CRITICAL closures

- **C1 — MFA bypass via REST refresh** — new login contract: MFA accounts get
  `200 { mfaRequired, mfaToken, sessionId }` (no tokens). `mfaToken` is a 600s JWT with
  scope `mfa:verify`; `POST /v1/identity/mfa/verify` exchanges it (after throttled,
  lockout-protected, audited TOTP/recovery check with used-step replay rejection) for
  `{ accessToken, refreshToken, mfaVerified: true }`. Inline `mfaCode` at login completes
  MFA in one round-trip. REST `/v1/auth/refresh` + OAuth refresh grant reject
  `mfaVerified=false` sessions (`authentication.mfa.required`).
- **C2 — unauthenticated GraphQL `rotateAppKey`/`revokeApp`** — both now require the
  app's live credentials (headers verified via `verify-app-api-key`, mutation id must
  match); `registerApp` requires an admin API key in production (same
  `ProductionAdminGuard` semantics as REST). `@Public()` removed from GraphQL.
- **C3 — plaintext tokens in outbox** — `plaintextToken` is AES-256-GCM encrypted at rest
  (`v1:<iv>:<tag>:<ct>`, key derived from `TOKEN_SECRET`); dead-lettered outbox rows are
  purged by age regardless of `processedAt`.

## HIGH closures (12/12)

- **H-1** GraphQL registerApp production-gated · **H-2** org-boundary checks on
  `adminUser`/`adminAuditLog`/`getUser` (cross-tenant → null/403) · **H-3** server-side
  app-scope registry (`app:register|auth:read|auth` — user scopes structurally
  impossible for app tokens) + `typ` claim discrimination in guards · **H-4**
  production-default rejection rewritten as cross-field Joi `when('NODE_ENV')` — now
  effective when `NODE_ENV` comes from `.env` only; `EMAIL_TRANSPORT=log` also rejected
  in production · **H-5a** TOTP secrets AES-256-GCM at rest (env `MFA_SECRET_KEY`,
  boot-required in prod) · **H-5b** `mfa/verify` throttled (60/5) + 5-failure/15-min
  per-session lockout + success/failure audit events · **H-6** global GraphQL Redis
  rate-limit guard (per-IP + per-email buckets) + 100-field validation rule ·
  **H-7** refresh reuse detection rebuilt: 60s grace for legit concurrent retries
  (`sessions.lastRotatedAt`), old-token-beyond-grace → family compromise +
  `authentication.refresh.reuse_detected`/`family_revoked` audits; false-positive
  mass-revoke removed · **H-8** account-wide lockout (10 fails/15min across IPs) +
  success clears counters + OAuth passes real IP + `extractEmail` reads `username` ·
  **H-9** log redaction covers `code`/`mfaCode`/`currentPassword`/`newPassword` ·
  **H-10** real audit dedup: `AuditLog.eventId` + `@@unique([eventType, eventId])`,
  handler passes domain event id, P2002 skip verified by new e2e · **H-11** per-listener
  trust proxy (`ADMIN_TRUST_PROXY_HOPS` default 0) · **H-12** confirmation cap: >10
  MFA-pending issuances/hour/email → generic 401 + `authentication.login.throttled`.

## MEDIUM / LOW

All ~20 MEDIUM and ~15 LOW items closed: org-slug no-op now throws; TOTP replay
tracking (Redis SETNX, 90s); TOTP window docs corrected (window 0); recovery-code
message oracle unified; MFA enrollment requires `currentPassword` + revokes other
sessions on enable; duplicate-register returns opaque 201 stub (email fingerprint
only in audit); P2002 register race → stub path; partial app headers → 400;
deferred domain auto-join on `identity.email.verified` (+ `identity.organization.joined_by_domain`
audit); password-reset enforces `Password.create` + `identity.password.reset` audit;
templates escape HTML + URL origin assertion; failed-login audit stores sha256-16
email fingerprint; `legacySha256` deleted; refresh/logout throttled; revoke uses path
param; `Math.random` → `randomBytes`; app errors uniform `app.credentials.invalid`;
introspection/playground default off in production; `verifyAccessToken` returns real
claims; admin search offset wired + ISO-date 400s + `callerKeyId` recorded; forged
`adminKeyId` removed from GraphQL; last-active admin key protected (409
`admin.key.last_active`); strict IPv4 octet parsing; fatal handlers drain + exit(1);
`/ready` generic failure text; helmet on docs paths; docker-compose bound to
localhost; expired sessions purged + missing indexes added; `Session.organizationId`
FK (SetNull); one-current-signing-key partial unique index; engagement FKs with
cascade; batched audit deletes; jwt key-cache expiry re-check; `ACCESS_TOKEN_TTL`
capped at 86400; `.env.example` complete; `typ:'user'` on user token issuance;
introspect allows app tokens; rotation P2002 → returns existing current key.

## New coverage added

`audit-log-dedup`, `account-lockout`, `refresh-reuse`, `admin-negative-auth`,
`production-admin-guard`, `graphql-mutation-auth-invariant` e2e specs (the invariant
spec pins that every SDL Mutation is auth-gated — this is the regression net that
would have caught C2). Unit suites for ip-allowlist strictness and MFA attempt tracker.

## Dependencies

`npm audit`: 34 (1 critical) → **33 (0 critical)** after non-breaking `npm audit fix`
(handlebars). Remaining all require breaking majors: `@graphql-tools/utils`/`braces`
(via @nestjs/graphql 13 — needs Nest 14), `deepmerge-ts`/`effect` (Prisma 6 — needs
Prisma 7), `nodemailer` (needs v10 + SMTP regression test); 20 moderate are dev-only
jest/istanbul chain. **Track: Nest 14 + Prisma 7 upgrade.**

## Residual notes (not audit findings)

- `issueAdminApiKey`/`revokeAdminApiKey` remain SDL-only (no resolvers) — implement or
  prune; the invariant spec pins them as known-public.
- GraphQL `RegisterAppInput` lacks `initialScopes` (REST-only parity gap).
- `prisma-session.repository.save()` upsert doesn't rewrite userId/familyId/orgId on
  update — cosmetic; specs avoid hardcoded session ids.
- Full e2e on this Windows host needs `--maxWorkers=2` (local resource limit; CI sets
  workers automatically).
- MFA two-step flow still inherently confirms password correctness, capped at 10
  confirmations/hour/account by the pending-issuance counter (documented accepted
  residual).
