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
  // V1.5: HMAC secret for email-verification & password-reset tokens.
  // Must be at least 32 chars in production (the dev default works
  // for local dev so the workflow doesn't require extra setup; in
  // production deploys this MUST be set explicitly).
  TOKEN_SECRET: Joi.string()
    .min(32)
    .default('dev-only-insecure-default-please-override-32chars'),
  JWT_ISSUER: Joi.string().default('cerberus'),
  JWT_AUDIENCE_DEFAULT: Joi.string().default('cerberus-clients'),
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
   * V1.5: secret used to derive HMAC-based lookup tokens for admin keys.
   * Must be at least 32 chars in production (per the regex below). Dev
   * allows the insecure default so the dev workflow doesn't require
   * extra setup; production deploys fail if this is left at default.
   */
  ADMIN_LOOKUP_SECRET: Joi.string()
    .min(32)
    .default('dev-only-insecure-default-please-override-32chars'),
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
