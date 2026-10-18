import Joi from 'joi';

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
  // (32 chars, satisfies the min). The startup-check below REJECTS
  // this default when NODE_ENV=production. Net result: dev workflow
  // still works without extra setup; production deploys fail at
  // boot if the operator forgot to override.
  TOKEN_SECRET: Joi.string()
    .min(32)
    .default('dev-only-insecure-default-please-override-32chars')
    .custom((value, helpers) => {
      if (
        process.env['NODE_ENV'] === 'production' &&
        value === 'dev-only-insecure-default-please-override-32chars'
      ) {
        return helpers.error('any.invalid', {
          message:
            'TOKEN_SECRET must be set to a real 32+ char value in production (not the dev default). Generate with: openssl rand -base64 48',
        });
      }
      // Joi's .custom() infers the callback value as `any`; the
      // return is forwarded into the validated value, which is
      // always a string here.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return value;
    }),
  // V1.7 audit fix #37: the dev default for JWT_ISSUER + the
  // audience is a predictable string. In production, an operator
  // who doesn't override it lets every service that knows the
  // default guess the `iss` claim. (Not a direct bypass — the
  // signing key is the real secret — but isop-invariant: the
  // operator should pick their own.)
  JWT_ISSUER: Joi.string()
    .default('cerberus')
    .custom((value, helpers) => {
      if (process.env['NODE_ENV'] === 'production' && value === 'cerberus') {
        return helpers.error('any.invalid', {
          message:
            'JWT_ISSUER must be set to a real value in production (not the dev default "cerberus")',
        });
      }
      // Joi's .custom() infers the callback value as `any`; the
      // return is forwarded into the validated value, which is
      // always a string here.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return value;
    }),
  JWT_AUDIENCE_DEFAULT: Joi.string()
    .default('cerberus-clients')
    .custom((value, helpers) => {
      if (
        process.env['NODE_ENV'] === 'production' &&
        value === 'cerberus-clients'
      ) {
        return helpers.error('any.invalid', {
          message:
            'JWT_AUDIENCE_DEFAULT must be set to a real value in production (not the dev default "cerberus-clients")',
        });
      }
      // Joi's .custom() infers the callback value as `any`; the
      // return is forwarded into the validated value, which is
      // always a string here.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return value;
    }),
  ACCESS_TOKEN_TTL: Joi.number().integer().positive().default(900),
  REFRESH_TOKEN_TTL: Joi.number().integer().positive().default(2_592_000),

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
    .default('dev-only-insecure-default-please-override-32chars')
    .custom((value, helpers) => {
      if (
        process.env['NODE_ENV'] === 'production' &&
        value === 'dev-only-insecure-default-please-override-32chars'
      ) {
        return helpers.error('any.invalid', {
          message:
            'ADMIN_LOOKUP_SECRET must be set to a real 32+ char value in production (not the dev default). Generate with: openssl rand -base64 48',
        });
      }
      // Joi's .custom() infers the callback value as `any`; the
      // return is forwarded into the validated value, which is
      // always a string here.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return value;
    }),
  ADMIN_IP_ALLOWLIST: Joi.string().allow('').default(''),

  // --------------------------------------------------------------------
  // Email transports
  // --------------------------------------------------------------------
  EMAIL_TRANSPORT: Joi.string().valid('log', 'smtp', 'sendgrid').default('log'),
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

  GRAPHQL_INTROSPECTION: Joi.boolean().default(true),
  GRAPHQL_PLAYGROUND: Joi.boolean().default(true),

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
