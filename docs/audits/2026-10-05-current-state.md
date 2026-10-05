# Cerberus — current state audit

**Date:** 2026-10-05
**Last commit:** `e0acf8a test(e2e): add C-1 + IpAllowlist + Throttle + fix DTO bug`

## Build & test gates

| Gate | Result |
|------|--------|
| `npm run build` | exit 0 |
| `npm run lint` | 0 errors, 0 warnings |
| `npm test` (unit) | **48 passed** in 3 suites |
| `npm run test:e2e` (integration) | **3 passed** in 3 suites |
| Docker (postgres+redis+mailpit) | all healthy |
| Both listeners boot | `:3000` public + `:3001` admin |

195 source `.ts` files, 3 `.spec.ts` files, 3 `.e2e-spec.ts` files, 9 Prisma migrations.

## What got shipped (last 6 commits)

```
e0acf8a test(e2e): add C-1 + IpAllowlist + Throttle + fix DTO bug
af2aac6 test(e2e): wire integration tests for H-1 + C-4 audit fixes
baa6310 test: drop in first unit tests + wire CI test job
b794bc1 build(deps): pin @prisma/client + prisma to ~6.16.3, @apollo/server to ~5.5.1
d7546b3 fix(graphql): register GraphqlDomainErrorFilter + export REDIS_CLIENT
e3630a2 fix(scalar): belt-and-suspenders CSP header removal on /api-docs
```

Two rounds of audit fixes (5 Critical + 6 High + 7 Medium + 5 Low + 17 QA + 6 second-reviewer) closed. Live verification confirmed:
- **Mail sender works**: register fires `EmailVerificationRequested` → `MailSenderDispatcher` → Mailpit receives email
- **Password reset works**: request fires `PasswordResetRequested` → MailSenderDispatcher → Mailpit receives email
- **JWT auth** working on all protected endpoints
- **GraphQL filter** surfaces `admin.forbidden` with `extensions.code: "FORBIDDEN"`

## Live verification I ran this session

```bash
$ curl -X POST /v1/identity/register -d '{"email":"smtp-test-...","password":"..."}'
{ "userId": "...", "organizationId": "...", ... }
status: 201

$ curl http://localhost:8026/api/v1/messages | jq .total
1  ← "Verify your Cerberus email address"

$ curl -X POST /v1/engagement/password-reset/request -d '{"email":"smtp-test-..."}'
status: 204

$ curl http://localhost:8026/api/v1/messages | jq '.messages | length'
2  ← + "Reset your Cerberus password"
```

The mail-sender chain I was previously worried about is in fact wired. It works in `EMAIL_TRANSPORT=log` (console) and `EMAIL_TRANSPORT=smtp` (Mailpit).

## Gaps I found this session

### Real, verified, ranked by user impact

1. **Audit log coverage is incomplete** — high impact
   - 23 event types defined in `audit-event-type.ts`
   - Only **13** actually written via `RecordAuditEventUseCase`
   - Live DB has 217 rows across only **6 distinct event types** (login.succeeded, user.registered, mfa.enabled, mfa.disabled, login.failed, user.mfa_disabled)
   - **Missing from code but in the allowlist:**
     - `authentication.account.locked` (when lockout kicks in)
     - `authorization.token.minted` / `authorization.token.revoked`
     - `engagement.email_verification.{requested,completed}` / `engagement.password_reset.{requested,completed}`
     - `admin.audit.searched`
     - `identity.account.locked` / `identity.email.verified`

2. **No body size limit / request timeout** — medium (DoS vector)
   - `src/apps/public-app.ts` and `admin-app.ts` set up Express but don't pass `app.use(json({ limit: '...' }))` or set a request timeout
   - A bad actor can POST arbitrary-size JSON or hold connections open

3. **Audit search `from`/`to` not applied at SQL** — medium
   - `admin-search-audit-log.use-case.ts` validates `from`/`to` but `loadByQuery()` ignores them
   - Documented in code as V1.5 work; surface area is admin-only

4. **App key rotation leaves old key alive** — medium
   - `rotate-app-api-key.use-case.ts` mints a new key, doesn't revoke the old
   - Two valid keys exist until `DELETE /v1/apps/:id` is called explicitly

5. **No `POST /admin/orgs`** — low
   - Orgs only created via user-registration. README acknowledges this as V1.5

6. **Outbox pattern not implemented** — high but already known
   - In-memory event bus: a process crash between DB commit and event publish drops the event
   - Most affects `MailSenderDispatcher` — user gets no email if process dies
   - Documented as V1.5 work

7. **No cron cleanup of expired rows** — low
   - `email_verifications`, `password_resets`, `sessions`, `mfa_secrets` grow forever
   - No retention policy

8. **Per-email rate limiting not implemented** — low
   - Login-attempt counter is per-IP, not per-email
   - An attacker rotating IPs can still brute-force one specific account

9. **Test coverage gaps** — medium
   - **Untested modules:** apps (register, rotate, revoke), authorization OAuth happy path, engagement `confirm-email-verification` and `confirm-password-reset`, admin `issue-admin-api-key` + `revoke-admin-api-key`
   - **No GraphQL query resolvers tested** — only `adminDisableUserMfa` mutation

10. **No coverage report in CI** — low
    - `npm run test:cov` exists, not wired into `.github/workflows/ci.yml`

11. **2 stale TODO comments** — low
    - `apps.controller.ts:25`: "TODO V2: gate by admin"
    - `argon2-password-hasher.ts:15`: "TODO V1.5: surface these as configurable"

## What I would do next

If the goal is "make this production-ready", the priority is:

| Priority | Item | Effort |
|----------|------|--------|
| **P0** | Wire the 10 missing audit events (item 1) | 2–3 hours — small edits to ~6 use-cases |
| **P1** | Add body-size limit + request timeout (item 2) | 30 min — two-line change in public-app.ts / admin-app.ts |
| **P1** | App key auto-revoke on rotate (item 4) | 1 hour — modify use-case + add test |
| **P1** | `POST /admin/orgs` (item 5) | 1 hour — new use-case + controller + test |
| **P2** | `from`/`to` SQL filter (item 3) | 2 hours — repo + use-case + test |
| **P2** | Add tests for the untested modules (item 9) | 1 day |
| **P2** | Coverage report in CI (item 10) | 30 min — add `jest --coverage` to the test job |
| **P3** | Outbox pattern (item 6) | 1–2 days — schema + transactional outbox + worker |
| **P3** | Cron cleanup (item 7) | 1 day — schedule + retention policy |
| **P3** | Per-email rate limiting (item 8) | 1 day — schema change + counter keying |

The P0+P1+P2 work is the minimum to call this a real V1.5 release. P3 items are nice-to-have but the service is functional without them.

## TL;DR

The audit fix work is **done and tested**. The remaining work is **feature-completeness for V1.5** — closing the small gap between "the V1 spec" and "what the README promises in the V1.5 roadmap". Most pressing user-visible issue is the **incomplete audit log coverage** (security teams expect to see who logged in when, who reset whose password, etc.).

Where do you want to go next?
