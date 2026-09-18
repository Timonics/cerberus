/**
 * Typed application configuration.
 *
 * Loaded once at boot by `@nestjs/config` and accessed by every component
 * via `ConfigService.get<AppConfig['key']>('key')`. The shape is the single
 * source of truth for runtime configuration; if you need a new env var,
 * add it here AND in `env.validation.ts`.
 *
 * Keys use dot-notation: `config.get('jwt.issuer')`, `config.get('database.url')`.
 */
export interface AppConfig {
  /** Node environment. */
  nodeEnv: 'development' | 'test' | 'production';

  /** HTTP port for the public API. */
  port: number;

  /** HTTP port for the admin API (separate surface, IP-allowlisted). */
  adminPort: number;

  /** Log level for Pino. */
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

  /** JWT signing parameters. */
  jwt: {
    issuer: string;
    audienceDefault: string;
    /** Access-token TTL in seconds (default: 15 minutes). */
    accessTokenTtl: number;
    /** Refresh-token TTL in seconds (default: 30 days). */
    refreshTokenTtl: number;
  };

  database: {
    url: string;
  };

  redis: {
    url: string;
  };

  admin: {
    /** Hashed admin API key (argon2id of the secret). Empty disables the admin API. */
    apiKeyHash: string;
    /** CIDR-allowlist of IPs that may reach the admin surface. Empty = deny all. */
    ipAllowlist: string[];
  };

  email: {
    transport: 'log' | 'smtp' | 'sendgrid';
    from: string;
    smtp: {
      host: string;
      port: number;
      user: string;
      password: string;
      secure: boolean;
    };
    sendgrid: {
      apiKey: string;
    };
  };

  rateLimit: {
    /** Sliding-window TTL in seconds. */
    ttl: number;
    /** Max requests per window per key. */
    max: number;
  };
}

/**
 * Configuration factory.
 *
 * Reads `process.env` directly — this function runs once at boot. Validation
 * (via Joi, in `env.validation.ts`) has already rejected invalid input by the
 * time this runs.
 */
export const configuration = (): AppConfig => {
  /** Parse a comma-separated env var into a string array. */
  const splitCsv = (value: string | undefined): string[] =>
    (value ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

  return {
    nodeEnv: (process.env.NODE_ENV as AppConfig['nodeEnv']) ?? 'development',
    port: Number(process.env.PORT ?? 3000),
    adminPort: Number(process.env.ADMIN_PORT ?? 3001),
    logLevel: (process.env.LOG_LEVEL as AppConfig['logLevel']) ?? 'info',

    jwt: {
      issuer: process.env.JWT_ISSUER ?? 'cerberus',
      audienceDefault: process.env.JWT_AUDIENCE_DEFAULT ?? 'cerberus-clients',
      accessTokenTtl: Number(process.env.ACCESS_TOKEN_TTL ?? 900),
      refreshTokenTtl: Number(process.env.REFRESH_TOKEN_TTL ?? 2_592_000),
    },

    database: {
      url:
        process.env.DATABASE_URL ??
        'postgresql://cerberus:cerberus@localhost:5432/cerberus',
    },

    redis: {
      url: process.env.REDIS_URL ?? 'redis://localhost:6379',
    },

    admin: {
      apiKeyHash: process.env.ADMIN_API_KEY_HASH ?? '',
      ipAllowlist: splitCsv(process.env.ADMIN_IP_ALLOWLIST),
    },

    email: {
      transport:
        (process.env.EMAIL_TRANSPORT as AppConfig['email']['transport']) ??
        'log',
      from: process.env.EMAIL_FROM ?? 'Cerberus <no-reply@cerberus.local>',
      smtp: {
        host: process.env.SMTP_HOST ?? 'localhost',
        port: Number(process.env.SMTP_PORT ?? 1025),
        user: process.env.SMTP_USER ?? '',
        password: process.env.SMTP_PASSWORD ?? '',
        secure: (process.env.SMTP_SECURE ?? 'false').toLowerCase() === 'true',
      },
      sendgrid: {
        apiKey: process.env.SENDGRID_API_KEY ?? '',
      },
    },

    rateLimit: {
      ttl: Number(process.env.RATE_LIMIT_TTL ?? 60),
      max: Number(process.env.RATE_LIMIT_MAX ?? 60),
    },
  };
};
