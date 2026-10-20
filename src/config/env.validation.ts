import Joi from 'joi';

/**
 * Known dev-only default secrets. Used as Joi defaults outside production
 * and rejected when `NODE_ENV=production` (V1.7 audit fixes #36/#37, and
 * audit 2026-10-19 H-4).
 */
const DEV_SECRET_DEFAULT = 'dev-only-insecure-default-please-override-32chars';

/**
 * Production rejection uses CROSS-FIELD `when('NODE_ENV', ...)` against
 * the validated object — NOT `process.env['NODE_ENV']`. @nestjs/config
 * validates the merged env-file + process.env object BEFORE assigning
 * env-file values into `process.env`, so a deployment that sets
 * `NODE_ENV=production` only in `.env` would otherwise boot with
 * `process.env.NODE_ENV === undefined` and silently pass these checks
 * (audit 2026-10-19 H-4).
 */

/**
 * Environment-variable validation schema.
 *
 * This runs once at boot, before any module is constructed. If any required
 * variable is missing or malformed, Nest refuses to start with a clear error
 * pointing at the offending variable. We deliberately use a permissive
 * default for things like `*_ALLOWLIST` (empty string = disabled feature)
 * rather than crashing the process — production should set them explicitly.
 */
export const envValidationSchema = Joi.object({
  // --------------------------------------------------------------------
  // Process / runtime
  // --------------------------------------------------------------------
  NODE_ENV: Joi.string()
    .valid('development', 'test', 'production')
    .default('development'),
  PORT: Joi.number().port().default(3000),
  ADMIN_PORT: Joi.number().port().default(3001),
  LOG_LEVEL: Joi.string()
    .valid('fatal', 'error', 'warn', 'info', 'debug', 'trace')
    .default('info'),

  // --------------------------------------------------------------------
  // JWT
  // --------------------------------------------------------------------
  // V1.7 audit fix #36: HMAC secret for email-verification &
  // password-reset tokens. Default is a known dev-only constant
  // (32 chars, satisfies the min). The cross-field `when` below REJECTS
  // this default when NODE_ENV=production. Net result: dev workflow
  // still works without extra setup; production deploys fail at
  // boot if the operator forgot to override.
  TOKEN_SECRET: Joi.string()
    .min(32)
    .when('NODE_ENV', {
      is: 'production',
      then: Joi.string()
        .min(32)
        .invalid(DEV_SECRET_DEFAULT)
        .required()
        .messages({
          'any.invalid':
            'TOKEN_SECRET must be set to a real 32+ char value in production (not the dev default). Generate with: openssl rand -base64 48',
          'any.required':
            'TOKEN_SECRET is required in production. Generate with: openssl rand -base64 48',
        }),
      otherwise: Joi.string().min(32).default(DEV_SECRET_DEFAULT),
    }),
  // V1.7 audit fix #37: the dev default for JWT_ISSUER + the
  // audience is a predictable string. In production, an operator
  // who doesn't override it lets every service that knows the
  // default guess the `iss` claim. (Not a direct bypass — the
  // signing key is the real secret — but the operator should pick
  // their own.)
  JWT_ISSUER: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.string().invalid('cerberus').required().messages({
      'any.invalid':
        'JWT_ISSUER must be set to a real value in production (not the dev default "cerberus")',
      'any.required':
        'JWT_ISSUER is required in production (not the dev default "cerberus")',
    }),
    otherwise: Joi.string().default('cerberus'),
  }),
  JWT_AUDIENCE_DEFAULT: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.string().invalid('cerberus-clients').required().messages({
      'any.invalid':
        'JWT_AUDIENCE_DEFAULT must be set to a real value in production (not the dev default "cerberus-clients")',
      'any.required':
        'JWT_AUDIENCE_DEFAULT is required in production (not the dev default "cerberus-clients")',
    }),
    otherwise: Joi.string().default('cerberus-clients'),
  }),
  // V1.7: 15 minutes. Audit 2026-10-19: capped at 24h — an
  // operator typo (e.g. an extra zero) must not mint day-long
  // bearer tokens.
  ACCESS_TOKEN_TTL: Joi.number().integer().positive().max(86_400).default(900),
  REFRESH_TOKEN_TTL: Joi.number().integer().positive().default(2_592_000),
  // 2026-10-19 audit fix C1: TTL (seconds) of the mfaToken issued at
  // login when MFA is still pending. 60s floor / 1h ceiling — a
  // pending token is a scoped credential; it should not outlive the
  // user's patience for completing the second factor by much.
  MFA_PENDING_TOKEN_TTL: Joi.number().integer().min(60).max(3600).default(600),
  /**
   * 2026-10-19 audit fix H-5a: master key for AES-256-GCM encryption of
   * TOTP secrets at rest. Same pattern as TOKEN_SECRET — dev default
   * allowed, production-rejected at boot when the default is used.
   */
  MFA_SECRET_KEY: Joi.string()
    .min(32)
    .default('dev-only-mfa-secret-key-please-override-32chars')
    .custom((value, helpers) => {
      if (
        process.env['NODE_ENV'] === 'production' &&
        value === 'dev-only-mfa-secret-key-please-override-32chars'
      ) {
        return helpers.error('any.invalid', {
          message:
            'MFA_SECRET_KEY must be set to a real 32+ char value in production (not the dev default). Generate with: openssl rand -base64 48',
        });
      }
      // Joi's .custom() infers the callback value as `any`; the
      // return is forwarded into the validated value, which is
      // always a string here.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return value;
    }),

  // --------------------------------------------------------------------
  // Datastores
  // --------------------------------------------------------------------
  DATABASE_URL: Joi.string()
    .uri({ scheme: ['postgres', 'postgresql'] })
    .required(),
  REDIS_URL: Joi.string()
    .uri({ scheme: ['redis', 'rediss'] })
    .required(),

  // --------------------------------------------------------------------
  // Admin API
  // --------------------------------------------------------------------
  ADMIN_API_KEY_HASH: Joi.string().allow('').default(''),
  /**
   * V1.7 audit fix #36: secret used to derive HMAC-based lookup
   * tokens for admin keys. Same pattern as TOKEN_SECRET above
   * (dev default, production-rejected at boot).
   */
  ADMIN_LOOKUP_SECRET: Joi.string()
    .min(32)
    .when('NODE_ENV', {
      is: 'production',
      then: Joi.string()
        .min(32)
        .invalid(DEV_SECRET_DEFAULT)
        .required()
        .messages({
          'any.invalid':
            'ADMIN_LOOKUP_SECRET must be set to a real 32+ char value in production (not the dev default). Generate with: openssl rand -base64 48',
          'any.required':
            'ADMIN_LOOKUP_SECRET is required in production. Generate with: openssl rand -base64 48',
        }),
      otherwise: Joi.string().min(32).default(DEV_SECRET_DEFAULT),
    }),
  ADMIN_IP_ALLOWLIST: Joi.string().allow('').default(''),

  // --------------------------------------------------------------------
  // Email transports
  // --------------------------------------------------------------------
  // Audit 2026-10-19: the `log` transport writes live password-reset /
  // email-verification URLs (including `?token=`) to stdout. Fine for
  // local dev, never for production — rejected via the same cross-field
  // mechanism as the secret defaults above.
  // Base schema is deliberately UNconstrained: Joi's `when()` keeps
  // the base as a fallback alternative, so a base-level `.valid(...)`
  // would let a rejected value slip through (verified empirically).
  EMAIL_TRANSPORT: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.string().valid('smtp', 'sendgrid').required().messages({
      'any.only':
        'EMAIL_TRANSPORT must be "smtp" or "sendgrid" in production — the "log" transport writes live tokens to stdout',
      'any.required':
        'EMAIL_TRANSPORT must be set to "smtp" or "sendgrid" in production (the dev "log" transport is rejected)',
    }),
    otherwise: Joi.string().valid('log', 'smtp', 'sendgrid').default('log'),
  }),
  EMAIL_FROM: Joi.string().default('Cerberus <no-reply@cerberus.local>'),
  EMAIL_PUBLIC_URL: Joi.string().uri().default('http://localhost:3000'),
  SMTP_HOST: Joi.string().default('localhost'),
  SMTP_PORT: Joi.number().port().default(1025),
  SMTP_USER: Joi.string().allow('').default(''),
  SMTP_PASSWORD: Joi.string().allow('').default(''),
  SMTP_SECURE: Joi.boolean().truthy('true').falsy('false').default(false),
  SENDGRID_API_KEY: Joi.string().allow('').default(''),

  // --------------------------------------------------------------------
  // Rate limiting
  // --------------------------------------------------------------------
  RATE_LIMIT_TTL: Joi.number().integer().positive().default(60),
  RATE_LIMIT_MAX: Joi.number().integer().positive().default(60),
  // Per-email rate limit (separate bucket). 0 disables. Default is
  // half of the per-IP max — login's @Throttle(60, 20) means a
  // legitimate user rotating IPs (laptop + phone) won't trip this.
  RATE_LIMIT_PER_EMAIL_MAX: Joi.number().integer().min(0).default(10),

  // V1.7: argon2id cost factors. Defaults match the pre-V1.7
  // hard-coded values. Prod should set ARGON2_MEMORY_COST
  // and ARGON2_TIME_COST to whatever brings verify time to
  // the 250–500ms range on the actual hardware.
  ARGON2_MEMORY_COST: Joi.number().integer().min(19_456).default(65_536),
  ARGON2_TIME_COST: Joi.number().integer().min(2).default(3),
  ARGON2_PARALLELISM: Joi.number().integer().min(1).max(16).default(1),

  // V1.7: ProductionAdminGuard. Forced on in production via the
  // guard's own NODE_ENV check; setting this to true also turns
  // it on in dev/staging. Default false.
  REQUIRE_ADMIN_FOR_REGISTRATION: Joi.boolean().default(false),

  // V1.5: HTTP hardening — body size + request/response timeouts.
  // Defaults match the values in src/config/configuration.ts; the
  // Joi schemas here just enforce the right type + range.
  HTTP_BODY_LIMIT_BYTES: Joi.number()
    .integer()
    .min(1024) // 1 KiB absolute floor — anything lower is unusable
    .max(10 * 1024 * 1024) // 10 MiB ceiling — anything higher is unbounded
    .default(102_400), // 100 KiB
  HTTP_REQUEST_TIMEOUT_MS: Joi.number()
    .integer()
    .positive()
    .min(1000) // 1s floor
    .max(5 * 60 * 1000) // 5min ceiling
    .default(30_000), // 30s
  HTTP_RESPONSE_TIMEOUT_MS: Joi.number()
    .integer()
    .positive()
    .min(1000)
    .max(10 * 60 * 1000) // 10min ceiling
    .default(30_000), // 30s
  // V1.7 audit fix #12
  TRUST_PROXY_HOPS: Joi.number().integer().min(0).max(32).default(1),
  // Audit 2026-10-19 H-11: the ADMIN listener gets its own knob and
  // defaults to 0 (never trust X-Forwarded-For). If the admin port is
  // directly reachable, a default of 1 lets any client spoof
  // `X-Forwarded-For: 127.0.0.1` and walk past the IP allowlist.
  // Operators behind a real reverse proxy set this explicitly.
  ADMIN_TRUST_PROXY_HOPS: Joi.number().integer().min(0).max(32).default(0),

  // Audit 2026-10-19: introspection + Playground default OFF in
  // production, ON elsewhere. The NODE_ENV decision is made HERE in
  // the validated record (cross-field `when`), not in
  // configuration.ts — which runs after Joi and would otherwise
  // make the call from raw process.env.
  GRAPHQL_INTROSPECTION: Joi.boolean().when('NODE_ENV', {
    is: 'production',
    then: Joi.boolean().default(false),
    otherwise: Joi.boolean().default(true),
  }),
  GRAPHQL_PLAYGROUND: Joi.boolean().when('NODE_ENV', {
    is: 'production',
    then: Joi.boolean().default(false),
    otherwise: Joi.boolean().default(true),
  }),

  // --------------------------------------------------------------------
  // V1.5 retention cleanup — see src/cleanup/ for the cron wiring.
  // Each table has its own TTL (hours or days). The cron schedule
  // is a standard 5-field expression; CLEANUP_SCHEDULE='' disables
  // the cron entirely.
  // --------------------------------------------------------------------
  CLEANUP_SCHEDULE: Joi.string().allow('').default('0 * * * *'),
  CLEANUP_EMAIL_VERIFICATION_TTL_HOURS: Joi.number()
    .integer()
    .min(0)
    .max(24 * 365)
    .default(0),
  CLEANUP_PASSWORD_RESET_TTL_HOURS: Joi.number()
    .integer()
    .min(0)
    .max(24 * 365)
    .default(0),
  CLEANUP_INVITATION_TTL_DAYS: Joi.number()
    .integer()
    .min(0)
    .max(3650)
    .default(30),
  CLEANUP_SESSION_TTL_DAYS: Joi.number().integer().min(0).max(3650).default(30),
  CLEANUP_APP_KEY_TTL_DAYS: Joi.number().integer().min(0).max(3650).default(90),
  CLEANUP_ADMIN_KEY_TTL_DAYS: Joi.number()
    .integer()
    .min(0)
    .max(3650)
    .default(90),
  CLEANUP_SIGNING_KEY_TTL_DAYS: Joi.number()
    .integer()
    .min(0)
    .max(3650)
    .default(7),
  CLEANUP_RECOVERY_CODE_TTL_DAYS: Joi.number()
    .integer()
    .min(0)
    .max(3650)
    .default(90),
  CLEANUP_OUTBOX_TTL_DAYS: Joi.number().integer().min(0).max(3650).default(7),
  // V1.7 audit fix #38: audit_logs retention. 0 = disabled.
  CLEANUP_AUDIT_LOG_TTL_DAYS: Joi.number()
    .integer()
    .min(0)
    .max(3650)
    .default(90),
});

/**
 * Validation options for `@nestjs/config`.
 *
 * `allowUnknown: true` — we don't own the whole env, only what we declare.
 * `abortEarly: false` — report every missing/invalid variable in one pass.
 */
export const envValidationOptions = {
  allowUnknown: true,
  abortEarly: false,
} as const;
