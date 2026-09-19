# Cerberus Postman Collection

Drop-in Postman collection for the Cerberus auth service. Covers every
REST endpoint plus the full GraphQL surface (`POST /graphql`).

## Files

| File | What it is |
|------|------------|
| `Cerberus.postman_collection.json` | The collection (v2.1 schema). Import this. |
| `Cerberus.dev.postman_environment.json` | Environment for `localhost:3000`. |
| `Cerberus.staging.postman_environment.json` | Environment for a staging URL (edit the `baseUrl` after import). |

## Import

1. Postman → **File → Import** → drop the three JSON files.
2. Select the **Cerberus — dev** environment in the top-right.
3. Set `baseUrl` if your server isn't on `http://localhost:3000`.

## First-time flow

Run in order:

1. **Health → GET /health** — confirm the server is up.
2. **OAuth2 → POST /v1/oauth/admin/keys/rotate** — only needed if your DB
   has no signing key yet (first run after `prisma migrate deploy`).
   The test script auto-saves `{{kid}}`.
3. **OAuth2 → POST /v1/oauth/token — password grant** — fills
   `{{bearerToken}}` and `{{refreshToken}}`.
4. **Identity → POST /v1/identity/register** — creates a user, fills
   `{{userId}}` and `{{organizationSlug}}`.
5. **GraphQL → Mutation: register** — same operation over GraphQL;
   useful for comparing REST vs GraphQL ergonomics.
6. **GraphQL → Query: me** — proves the bearer token round-trips.

Then run the **Examples — chained flows** folder for pre-built scenarios.

## Conventions used in this collection

### Auth headers

| Endpoint family | Header |
|------------------|--------|
| OAuth2 + JWKS | none (public) |
| `/v1/auth/*` | `Authorization: Bearer {{bearerToken}}` |
| `/v1/identity/mfa/*`, `/v1/identity/change-password`, `/v1/identity/me`, `/v1/engagement/audit-log/me`, `/v1/engagement/email-verification/request` | `X-User-Id: {{userId}}` (Phase 11 placeholder — replaced with JWT in Phase 13) |
| GraphQL (except `health`, `jwks`, `verifyAccessToken`) | `Authorization: Bearer {{bearerToken}}` |

### Auto-extracted env vars

The `tests` scripts on each request auto-populate collection variables.
You'll see them update in the **Environments → Cerberus — dev** panel
in real time.

| Trigger | Var captured |
|---------|--------------|
| OAuth token (password or refresh) | `bearerToken`, `refreshToken`, `expiresIn` |
| Auth login | `currentSessionId`, `currentFamilyId` + tokens |
| Identity register | `userId`, `organizationSlug` |
| MFA enable | `mfaSecret`, `recoveryCodes` (JSON array), `recoveryCode1` |
| JWKS fetch | `kid` |
| OAuth key rotate | `kid` |
| GraphQL verifyAccessToken | `verifiedSub`, `verifiedOrg`, `verifiedRole`, `verifiedScope` |
| Any successful response | `lastRequestId` (from `X-Request-Id` header) |

### TOTP auto-computation

The requests that need a fresh TOTP code (`/mfa/confirm`,
`/mfa/disable`, `GraphQL confirmMfaEnrollment`, `GraphQL disableMfa`,
`GraphQL verifyMfa`) have a **prerequest** script that computes the
6-digit code from `{{mfaSecret}}` using RFC 6238 (HMAC-SHA1, 30-second
timestep, 6 digits). Run `/mfa/enable` first, then those requests
just work.

### Token replay tests

| Request | Expected failure on replay |
|---------|----------------------------|
| `/v1/auth/refresh` after a successful refresh | 401 (token already rotated) |
| `/v1/engagement/email-verification/confirm` after first call | 400 |
| `/v1/engagement/password-reset/confirm` after first call | 400 |

### Getting verification + reset tokens

These tokens are emailed (in production) or logged (in dev with
`EMAIL_TRANSPORT=log`). In dev they're visible in the server log:
`[email] to=... subject=Verify your Cerberus email address text=...
?token=...`. Paste the token into `{{emailVerificationToken}}` or
`{{passwordResetToken}}` before running the `confirm` requests.

With `EMAIL_TRANSPORT=smtp` and Mailpit on `localhost:8026`, fetch them
from the Mailpit web UI instead.

## Environment variables

| Key | Default | Notes |
|-----|---------|-------|
| `baseUrl` | `http://localhost:3000` | Server root. |
| `bearerToken` | empty | Auto-filled by login requests. |
| `refreshToken` | empty | Auto-filled by login requests. |
| `expiresIn` | `900` | Access-token TTL in seconds. |
| `accessTokenTtl` | `900` | Mirror (used in some custom checks). |
| `userId` | empty | Auto-filled by `/v1/identity/register`. |
| `currentSessionId` | empty | Auto-filled by `/v1/auth/login`. |
| `currentFamilyId` | empty | Auto-filled by `/v1/auth/login`. |
| `otherSessionId` | empty | Set manually for the cross-user revoke test. |
| `organizationSlug` | empty | Auto-filled by `/v1/identity/register`. |
| `kid` | empty | Auto-filled by JWKS fetch / key rotation. |
| `mfaSecret` | empty | Auto-filled by `/mfa/enable`. |
| `totpCode` | empty | Auto-computed by prerequest scripts. |
| `recoveryCodes` | `[]` | Auto-filled by `/mfa/enable`. |
| `recoveryCode1` | empty | First recovery code, for `/mfa/verify` tests. |
| `emailVerificationToken` | empty | Paste from server log / Mailpit. |
| `passwordResetToken` | empty | Paste from server log / Mailpit. |
| `verifiedSub`, `verifiedOrg`, `verifiedRole`, `verifiedScope` | empty | Auto-filled by GraphQL `verifyAccessToken`. |
| `lastRequestId` | empty | Auto-filled by every response (X-Request-Id). |

## Regenerating

The collection is generated from `scripts/gen-postman-collection.js`.
Edit that script and run `node scripts/gen-postman-collection.js` to
regenerate. The script is the source of truth — the JSON files are
artifacts.

## What this collection covers

### REST (Phases 11–14)

- **Health:** `/health`, `/ready`
- **Auth:** login, refresh, logout, list sessions, revoke session
- **OAuth2:** password grant, refresh_token grant, introspect, revoke, JWKS, admin key rotation
- **Identity:** register, change-password, update-display-name, MFA lifecycle (enable / confirm / disable / verify)
- **Engagement:** email verification (request / confirm), password reset (request / confirm), audit log

### GraphQL (Phase 14.5)

- Introspection query (full schema dump)
- Query: `health`, `me`, `getUser`, `jwks`, `verifyAccessToken`, `myAuditLog`
- Mutation: `register`, `changePassword`, `updateDisplayName`, `enableMfa`, `confirmMfaEnrollment`, `disableMfa`, `verifyMfa`, `requestEmailVerification`, `confirmEmailVerification`, `requestPasswordReset`, `confirmPasswordReset`

### Examples (chained scenarios)

- **New user happy path:** register → login → call `/me` over GraphQL → list sessions.
- **Password reset flow:** request reset → confirm with new password → re-login with the new password.
