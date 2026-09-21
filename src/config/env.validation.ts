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

  GRAPHQL_INTROSPECTION: Joi.boolean().default(true),
  GRAPHQL_PLAYGROUND: Joi.boolean().default(true),
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
