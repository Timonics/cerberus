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
| `redis`        | Redis (Valkey) plugin     | Railway injects `REDIS_URL`                                      |
| (optional) SMTP | any SMTP provider        | Use `EMAIL_TRANSPORT=smtp` or `sendgrid`; no Railway plugin needed |

Postgres can be either the Railway PostgreSQL plugin (`${{Postgres.DATABASE_URL}}`)
or an external provider such as Supabase — see the next section.

### Postgres via Supabase

`schema.prisma` uses the Supabase pattern — pooled runtime connection plus a
direct migration connection:

```prisma
datasource db {
  url       = env("DATABASE_URL")  // Supabase pooler (PgBouncer), port 6543
  directUrl = env("DIRECT_URL")    // Supabase direct connection, port 5432
}
```

Set BOTH as plain variables on the cerberus service (Supabase is external to
Railway, so no `${{...}}` reference — paste the strings):

- **`DATABASE_URL`** — the **Connection Pooling** string from Supabase
  (Project Settings → Database; host `...pooler.supabase.com`, port 6543)
  with `?sslmode=require&pgbouncer=true` appended. `pgbouncer=true` stops
  Prisma using prepared statements, which PgBouncer's transaction pooling
  breaks.
- **`DIRECT_URL`** — the **direct** connection string (port 5432).
  `prisma migrate deploy` uses it automatically. Schema validation fails
  (P1012) if either variable is missing — which is what blocks first-deploy
  migrations until both are set.

Caveats: queries now cross the public internet — pick a Supabase region
close to Railway (`us-west1`) when you can; it's fine for an auth service's
query patterns. The pooler also handles connection limits so the app's pool
never exhausts Supabase.

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

A gated DAG (`.github/workflows/ci.yml`) runs on every push to `master` and
every PR:

- **verify** — prettier check, ESLint, unit tests, build, artifact check.
- **integration** *(needs verify)* — migrations, server-boot smoke test,
  full e2e suite against service-container Postgres + Redis.
- **security** *(needs verify)* — `npm audit --audit-level=critical` and a
  Trivy filesystem scan (lockfile, config, secrets), CRITICAL-gated.
- **sbom** *(needs verify)* — CycloneDX SBOM via syft (uploaded as a 30-day
  artifact), license gate (`scripts/check-licenses.mjs`), Trivy SBOM scan
  against OSV/NVD.
- **docker** *(needs integration + security + sbom)* — image build + Trivy
  image scan. **No push** — Railway deploys from the repo, so the image
  exists purely to prove the Dockerfile produces a clean runtime. (Flip
  `push:` on and add GHCR login + `packages: write` if a registry path is
  ever needed.)
- **dependency review** *(PRs only)* — blocks dependency changes introducing
  CRITICAL vulnerabilities or copyleft licenses.

Railway's GitHub integration deploys from `master` after these checks pass —
enable "wait for CI" in the Railway service settings (Deployments → Build
settings → check runs) so a red pipeline never reaches production.

### Vulnerability triage policy

Baseline at time of writing: **0 critical**, 10 high, 23 moderate, 5 low.
Criticals block the pipeline, full stop. High/moderate findings are triaged
manually; several are dev-only (jest/typescript-eslint chain) and do not
ship. Every security gate in `ci.yml` is CRITICAL-only — tighten them all
to HIGH (and `fail-on-severity: high` in the dependency-review job) once
the high-severity backlog is cleared.

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
