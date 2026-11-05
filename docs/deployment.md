# Cerberus — deployment guide (Railway)

This document covers deploying Cerberus to [Railway](https://railway.app):
service layout, required environment variables, migrations, and how the
GitHub pipeline gates releases.

## 1. Service layout

Cerberus runs as a single Node process with two HTTP listeners (public
`:PORT`, admin `:ADMIN_PORT`). On Railway, provision:

| Service        | Railway plugin          | Notes                                                            |
| -------------- | ----------------------- | ---------------------------------------------------------------- |
| `cerberus`     | GitHub repo (this one)  | Node 22 runtime, builds and starts from the repo                 |
| `postgres`     | PostgreSQL plugin       | Railway injects `DATABASE_URL`                                   |
| `redis`        | Redis (Valkey) plugin     | Railway injects `REDIS_URL`                                      |
| (optional) SMTP | any SMTP provider        | Use `EMAIL_TRANSPORT=smtp` or `sendgrid`; no Railway plugin needed |

Reference the Postgres/Redis variables from the app service (`${{Postgres.DATABASE_URL}}`,
`${{Redis.REDIS_URL}}`) or set them manually.

## 2. Build & start commands

Railway's Nixpacks builder detects Node automatically. To be explicit, set:

- **Build command:** `npm ci --legacy-peer-deps && npx prisma generate && npm run build`
- **Start command:** `npx prisma migrate deploy && node dist/main.js`

The `prisma migrate deploy` in the start command applies pending migrations
on every deploy before the server binds — it is idempotent and fails loudly
rather than skipping. Remove it from start and run migrations manually if you
prefer deploy-time control (`railway run npx prisma migrate deploy`).

The repo contains a `Dockerfile` (node:22-alpine, multi-stage) — you can
switch the service to Dockerfile deploys later; both paths produce the same
runtime.

## 3. Required environment variables

Generate secrets with `openssl rand -base64 48`. **The dev defaults are
rejected at boot when `NODE_ENV=production`.**

| Variable              | Purpose                                                        |
| --------------------- | -------------------------------------------------------------- |
| `NODE_ENV`            | `production`                                                   |
| `TOKEN_SECRET`        | HMAC secret for access/refresh/MFA-pending tokens (32+ chars)  |
| `ADMIN_LOOKUP_SECRET` | HMAC secret for admin lookup tokens (32+ chars)                |
| `MFA_SECRET_KEY`      | HMAC secret for MFA-pending login tokens (32+ chars)           |
| `JWT_ISSUER` / `JWT_AUDIENCE_DEFAULT` | Issuer/audience claims                      |
| `ADMIN_API_KEY_HASH`  | argon2 hash of the admin API key. Generate: `node -e "require('argon2').hash(process.argv[1]).then(console.log)" "your-key"` |
| `EMAIL_TRANSPORT`     | `smtp` (set `SMTP_*`) or `sendgrid` (set `SENDGRID_API_KEY`)   |

Inherited from Railway plugins: `DATABASE_URL`, `REDIS_URL`. `PORT` is set by
Railway (public listener); set `ADMIN_PORT=3001` as a separate variable.

### Admin listener exposure

The admin listener (`ADMIN_PORT`) enforces an IP allowlist
(`ADMIN_IP_ALLOWLIST`). Railway apps sit behind a shared load balancer with
varying egress IPs, so the allowlist alone will not recognize you. Options,
in order of preference:

1. **Keep the admin port unexposed.** Do not create a public domain/port
   mapping for `ADMIN_PORT`; reach it via `railway run` / private network
   only. `ADMIN_IP_ALLOWLIST=127.0.0.1/32` then still works for local
   tunnels, and the port is unreachable from the internet.
2. If you must expose it, set `ADMIN_TRUST_PROXY_HOPS=1` **and** restrict
   `ADMIN_IP_ALLOWLIST` to your office/static egress IPs. Never set
   `ADMIN_TRUST_PROXY_HOPS=1` while allowing `0.0.0.0/0`.

## 4. Release pipeline (GitHub Actions)

Two workflows gate every push to `master` and every PR:

- **CI** (`.github/workflows/ci.yml`) — three parallel jobs:
  - `ci`: install, build, verify OpenAPI/SDL artifacts, lint
    (max-warnings 0), apply migrations against a fresh Postgres, boot the
    server, smoke-test public + admin endpoints.
  - `test`: unit tests with the coverage gate, then the full e2e suite
    against service-container Postgres + Redis.
  - `supply-chain`: **npm audit** (fails on any CRITICAL vulnerability),
    **license policy check** (production deps must use permissive licenses
    — the allowlist is the `licenses:check` script in `package.json`),
    and **SBOM generation** (CycloneDX, production dependencies only).
    The SBOM is uploaded as a 30-day workflow artifact (`cerberus-sbom`).
- **Dependency Review** (`.github/workflows/dependency-review.yml`) — PRs
  only. Fails if the PR introduces a CRITICAL vulnerability or a copyleft
  license (GPL/AGPL/LGPL/SSPL/BUSL/Elastic), and posts a summary comment.

Railway's GitHub integration deploys from `master` after these checks pass —
enable "wait for CI" in the Railway service settings (Deployments → Build
settings → check runs) so a red pipeline never reaches production.

### Vulnerability triage policy

Baseline at time of writing: **0 critical**, 10 high, 23 moderate, 5 low.
Criticals block the pipeline, full stop. High/moderate findings are triaged
manually; several are dev-only (jest/typescript-eslint chain) and do not
ship. To tighten the gate later, change `--audit-level=critical` to
`high` in `ci.yml` and `fail-on-severity: high` in
`dependency-review.yml` once the backlog is cleared.

## 5. Post-deploy verification

```bash
curl -sf https://<your-domain>/health
curl -sf https://<your-domain>/.well-known/jwks.json
```

Then run a register → verify-email → login cycle against the public API and
check `GET /admin/audit-log` (via private network / tunnel) for the
corresponding `identity.*` / `authentication.*` events.

## 6. Rollback

Railway keeps prior deployments — redeploy a previous image from the
Deployments tab. Database rollbacks are manual: `prisma migrate resolve`
+ restore, or forward-fix with a new migration (preferred).
