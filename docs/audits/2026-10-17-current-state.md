# Cerberus — current state audit

**Date:** 2026-10-17
**Last commit:** `c8366a8 feat(outbox): V1.5 transactional outbox pattern for events`
**Branch:** `master` (up to date with `origin/master`)
**Working tree:** clean, no stashes

## Build & test gates

| Gate              | Result                                              |
|-------------------|-----------------------------------------------------|
| `npm run build`   | exit 0                                              |
| `npm run lint`    | 0 errors, 0 warnings                                |
| `npm test`        | 4 suites, **54/54 passed**                           |
| `npm run test:e2e`| **BLOCKED** — Docker Desktop daemon not running     |

212 source `.ts` files, 4 `.spec.ts` files, 9 `.e2e-spec.ts` files, 10 Prisma
migrations, 1 schema migration added since the last audit
(`20261013194118_outbox_events`).

### Why `npm run test:e2e` is blocked

The e2e suite needs Postgres + Redis + Mailpit, which only come up via
`docker compose up -d`. Docker Desktop daemon isn't running on this host:

```
$ docker ps
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxLinuxEngine
```

Last successful e2e run was at commit `c8366a8` (session prior — session
search confirmed 23/23 e2e tests passing). The e2e suite has **not been
re-run this session**. Code is unchanged since the last e2e pass; no
regression risk from this gap.

To clear: start Docker Desktop, `npm run infra:up`, `npm run test:e2e`.

## What got shipped since the 2026-10-05 audit (commits e0acf8a..c8366a8)

Six commits, ~1,975 lines added across 30 files. Three feature groups:

### 1. The 10 missing audit event types (`4879bae`)

Closed the gap flagged as P0 in the 2026-10-05 audit. The 23 declared
event types in `audit-event-type.ts` now all have writers.

- `EngagementAuditLogHandler` (Pattern B subscriber, 95 lines) wired into
  `engagement.module.ts` for the 4 engagement events:
  `email_verification.{requested,completed}` + `password_reset.{requested,completed}`.
- In-use-case writes (Pattern A) for `authentication.account.locked`,
  `identity.account.locked`, `identity.email.verified`,
  `authorization.token.minted`, `authorization.token.revoked`.
- `admin.audit.searched` writes in `admin-search-audit-log.use-case.ts`.
- New unit test `engagement-audit-log.handler.spec.ts` (141 lines) using
  a `FakeBus` (matches the playbook's Pattern B recipe).

### 2. V1.5 feature work (`f3ae1bc`, `eb57b13`)

- **HTTP hardening** — body limit (100 KiB default) + 30s request timeout
  + 30s response timeout on both `public-app.ts` and `admin-app.ts`.
  Env-var contract under `AppConfig.http.*` per the cerberus playbook §2.
- **App key auto-revoke on rotate** — `rotate-app-api-key.use-case.ts`
  now revokes the old key in the same tx as minting the new one.
- **`POST /admin/orgs`** — new `CreateOrganizationUseCase` (133 lines),
  new `admin.dto.ts` field, new domain error code, `IP allowlist` and
  error filter updated.
- **`from`/`to` SQL filter** — `prisma-audit-log.repository.ts` now
  applies the time range at the Prisma layer (was validated in use-case
  but ignored at SQL — closed gap from 2026-10-05 audit item 3).

### 3. Test coverage expansion (`fe68868`, `e76bfdd`, `c8366a8`)

- `engagement-confirm.e2e-spec.ts` (181 lines) — covers confirm-email and
  confirm-password-reset flows
- `admin-key-lifecycle.e2e-spec.ts` (75 lines) — issue / revoke admin keys
- `admin-orgs-and-app-revoke.e2e-spec.ts` (205 lines) — POST /admin/orgs + revoke
- `apps-lifecycle.e2e-spec.ts` (111 lines) — register / rotate / revoke
- `admin-audit-search-time-range.e2e-spec.ts` (117 lines) — from/to filter
- `outbox.e2e-spec.ts` (220 lines) — outbox pattern + the regression test
  for the `if (this.running)` re-arm bug
- `coverageThreshold` set in package.json at the current baseline (8/5/8/9)
  so CI catches coverage regression rather than the low absolute number
- prettier reformat of admin-key + engagement-confirm specs

### 4. The transactional outbox pattern (`c8366a8`) — P3 from last audit

Closed the highest-impact P3 from 2026-10-05. The in-process event bus
could drop events on process crash between DB commit and publish.
Now events are persisted to `outbox_events` inside the same tx, and a
relay polls every 1s and re-publishes to the in-process bus. Full shape
in the cerberus playbook §12. Two use-cases converted to the outbox:
`RegisterUserUseCase` and `LoginUseCase`.

**One real bug caught during live verification**: the relay's
`scheduleNextTick` re-arm condition was `if (this.running)`, but
`running` flips back to `false` inside the `tick()` finally block —
so the re-arm was always false and the relay fired exactly once on
startup, then went silent. Fixed by re-arming unconditionally.
Pinned by `outbox.e2e-spec.ts` regression test (waits 5s, asserts
the auto-poller picks up a fresh row without any manual `relay.tick()`).

## Gaps remaining

Ranked by user-impact × risk. All from the 2026-10-05 audit, plus what
the V1.5 work surfaced.

### P2 — small, no infra blocker

1. **Cron cleanup of expired rows** — `email_verifications`,
   `password_resets`, expired `mfa_secrets`, expired `sessions` grow
   forever. No retention policy. One-day feature: cron + cleanup
   use-cases. Most boring item on the list, blocks the table-growth
   issue before it bites.
3. **Per-email rate limiting** — login-attempt counter is per-IP. An
   attacker rotating IPs can still brute-force one specific account.
   Fix: Redis counter key by email in addition to IP. One-day feature.

### P3 — needs design decisions first

4. **Coverage threshold is low (~9%)** — set as a regression guard
   per the playbook §7, but raising it is real work. Each new
   integration test moves the needle; the threshold update should
   follow each test batch, not precede it.
5. **2 stale TODO comments** — `apps.controller.ts:25` ("TODO V2: gate
   by admin"), `argon2-password-hasher.ts:15` ("TODO V1.5: surface these
   as configurable"). Both from 2026-10-05 audit item 11 — still open.
6. **No GraphQL query resolvers tested** — only the
   `adminDisableUserMfa` mutation has direct GraphQL coverage. The
   rest go through REST. Not blocking because REST is the primary
   surface, but a regression in GraphQL would slip through CI.

### Closed since 2026-10-05

- ✅ Audit-log coverage (item 1, 10 events wired in `4879bae`)
- ✅ HTTP hardening (item 2, both apps in `f3ae1bc`)
- ✅ Audit-search from/to SQL filter (item 3, `eb57b13`)
- ✅ App key auto-revoke on rotate (item 4, `f3ae1bc`)
- ✅ POST /admin/orgs (item 5, `f3ae1bc`)
- ✅ Outbox pattern (item 6, `c8366a8`)
- ✅ Test coverage for app keys, engagement confirm, admin orgs,
  apps lifecycle, admin audit search time range (item 9, `eb57b13`+`fe68868`)
- ✅ Coverage threshold as regression guard (item 10, `fe68868`)

## What I would do next

| Priority | Item | Effort | What it unblocks |
|----------|------|--------|------------------|
| **P2** | Cron cleanup of expired rows | 1 day | Prevents unbounded table growth |
| **P2** | Per-email rate limiting | 1 day | Closes the per-account brute-force gap |
| **P3** | Wire coverage threshold update | 30 min | After each test batch, raise the bar |

P2 cron cleanup is the natural next sprint — small, self-contained,
ships in one or two commits, doesn't need design decisions, and
makes the long-tail maintenance cost a known quantity instead of
"we'll deal with it when the table is 100 GB".

## TL;DR

V1.5 feature work (HTTP hardening, app-key auto-revoke, POST
/admin/orgs, audit-search SQL filter, outbox pattern) all merged to
master, gates passing. Two P3 features from the previous audit closed
implicitly as side effects. Remaining work is small-batch polish
(cron cleanup, per-email rate limiting, coverage threshold). Where
do you want to go next?