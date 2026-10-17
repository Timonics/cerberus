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
  /** V1.5: server-side HMAC secret for email-verification & password-reset
   * tokens. Rotating this invalidates all outstanding tokens (intentional
   * fail-secure — same pattern as JWT signing keys). 32+ chars required. */
  tokenSecret: string;
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
    /**
     * V1.5: secret used as the HMAC key when computing the admin-key
     * lookup token. Generate via `openssl rand -hex 32`. Same secret
     * across all app instances — rotating it invalidates ALL admin
     * keys at once (intentional fail-secure).
     */
    lookupSecret: string;
    /** CIDR-allowlist of IPs that may reach the admin surface. Empty = deny all. */
    ipAllowlist: string[];
  };

  email: {
    transport: 'log' | 'smtp' | 'sendgrid';
    from: string;
    /**
     * Public base URL used to build email verification + password
     * reset links. Defaults to `http://localhost:3000` in dev. In
     * production, set to the externally-reachable URL (e.g.
     * `https://auth.example.com`).
     */
    publicUrl: string;
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

  /**
   * V1.5 HTTP hardening: explicit limits for body size and request
   * timeout. Without these, a malicious client can POST arbitrary
   * payloads or hold a connection open indefinitely.
   */
  http: {
    /**
     * Max accepted JSON body size, as a raw byte count.
     * Default: 100 KiB. The largest legitimate request is the JWKS
     * payload (a few KB); 100 KiB is comfortable headroom.
     */
    bodyLimitBytes: number;
    /**
     * Hard timeout for receiving the request headers + body. If a
     * client can't send the full request in this time, the
     * connection is closed.
     */
    requestTimeoutMs: number;
    /**
     * Hard timeout for sending the response. If a handler takes
     * longer than this, the response is closed.
     */
    responseTimeoutMs: number;
  };

  /**
   * V1.5 retention policy — how long to keep expired/revoked rows
   * before the cleanup cron deletes them. Each table has its own
   * TTL; see the audit at docs/audits/<date>-current-state.md for
   * the rationale per table. Set any value to 0 to disable cleanup
   * for that table (rows live forever).
   */
  cleanup: {
    /** Cron expression. Default: `0 * * * *` (top of every hour). */
    schedule: string;
    /** Email verifications: delete when `expiresAt < now()`. */
    emailVerificationTtlHours: number;
    /** Password resets: delete when `expiresAt < now()`. */
    passwordResetTtlHours: number;
    /** Invitations: delete when `expiresAt < now() - ttl`. */
    invitationTtlDays: number;
    /** Sessions: delete when `revokedAt < now() - ttl`. */
    sessionTtlDays: number;
    /** App API keys: delete when `revokedAt < now() - ttl`. */
    appKeyTtlDays: number;
    /** Admin API keys: delete when `revokedAt < now() - ttl`. */
    adminKeyTtlDays: number;
    /** Signing keys: delete when `isCurrent=false AND expiresAt < now() - ttl`. */
    signingKeyTtlDays: number;
    /** Recovery codes: delete when `usedAt < now() - ttl`. */
    recoveryCodeTtlDays: number;
    /** Outbox events: delete when `processedAt < now() - ttl`. */
    outboxTtlDays: number;
  };

  graphql: {
    /** Enable GraphQL introspection (SDL schema). */
    introspectionEnabled: boolean;
    /** Enable the GraphQL Playground (dev only). */
    playgroundEnabled: boolean;
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

    tokenSecret:
      process.env.TOKEN_SECRET ??
      // Fail-secure default for dev. In production, the Joi validator
      // requires an explicit value (32+ chars).
      'dev-only-insecure-default-please-override-32chars',
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
      lookupSecret:
        process.env.ADMIN_LOOKUP_SECRET ??
        // Fail-secure default: deterministic in dev so the same key
        // produces the same lookupToken across restarts. In production
        // this MUST be set explicitly (Joi validation requires it).
        'dev-only-insecure-default-please-override',
      ipAllowlist: splitCsv(process.env.ADMIN_IP_ALLOWLIST),
    },

    email: {
      transport:
        (process.env.EMAIL_TRANSPORT as AppConfig['email']['transport']) ??
        'log',
      from: process.env.EMAIL_FROM ?? 'Cerberus <no-reply@cerberus.local>',
      publicUrl: process.env.EMAIL_PUBLIC_URL ?? 'http://localhost:3000',
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

    http: {
      bodyLimitBytes: Number(process.env.HTTP_BODY_LIMIT_BYTES ?? 102_400), // 100 KiB
      // 30s request timeout — generous for slow clients but not
      // long enough for an attacker to keep a connection open.
      requestTimeoutMs: Number(process.env.HTTP_REQUEST_TIMEOUT_MS ?? 30_000),
      // 30s response timeout — handlers that take longer than this
      // are pathological and should fail loud, not hang.
      responseTimeoutMs: Number(process.env.HTTP_RESPONSE_TIMEOUT_MS ?? 30_000),
    },

    cleanup: {
      // Default: top of every hour. Tests + dev can override to a
      // less common schedule (e.g. nightly). Setting
      // CLEANUP_SCHEDULE='' disables the cron entirely.
      schedule: process.env.CLEANUP_SCHEDULE ?? '0 * * * *',
      // 0 = delete expired rows immediately; positive = keep them
      // around for an additional grace window before deletion.
      emailVerificationTtlHours: Number(
        process.env.CLEANUP_EMAIL_VERIFICATION_TTL_HOURS ?? 0,
      ),
      passwordResetTtlHours: Number(
        process.env.CLEANUP_PASSWORD_RESET_TTL_HOURS ?? 0,
      ),
      invitationTtlDays: Number(process.env.CLEANUP_INVITATION_TTL_DAYS ?? 30),
      sessionTtlDays: Number(process.env.CLEANUP_SESSION_TTL_DAYS ?? 30),
      appKeyTtlDays: Number(process.env.CLEANUP_APP_KEY_TTL_DAYS ?? 90),
      adminKeyTtlDays: Number(process.env.CLEANUP_ADMIN_KEY_TTL_DAYS ?? 90),
      signingKeyTtlDays: Number(process.env.CLEANUP_SIGNING_KEY_TTL_DAYS ?? 7),
      recoveryCodeTtlDays: Number(
        process.env.CLEANUP_RECOVERY_CODE_TTL_DAYS ?? 90,
      ),
      outboxTtlDays: Number(process.env.CLEANUP_OUTBOX_TTL_DAYS ?? 7),
    },

    graphql: {
      introspectionEnabled:
        (process.env.GRAPHQL_INTROSPECTION ?? 'true').toLowerCase() === 'true',
      playgroundEnabled:
        (process.env.GRAPHQL_PLAYGROUND ?? 'true').toLowerCase() === 'true',
    },
  };
};
