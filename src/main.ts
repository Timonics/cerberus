import 'reflect-metadata';
import { ConfigService } from '@nestjs/config';
import { Logger as PinoLogger } from 'nestjs-pino';
import type { INestApplication } from '@nestjs/common';
import { AppConfig } from './config/configuration';
import { bootstrapPublicApp } from './apps/public-app';
import { bootstrapAdminApp } from './apps/admin-app';

/**
 * Process entrypoint.
 *
 * Boots TWO NestApplications in the same process:
 *
 *   1. **Public app** — serves `/health`, `/ready`, `/.well-known/jwks.json`,
 *      all `/v1/*` routes (identity / auth / OAuth / engagement), and
 *      `/graphql`. Listens on `PORT` (default 3000).
 *
 *   2. **Admin app** — serves `/admin/*` (api-keys, users, audit-log).
 *      Listens on `ADMIN_PORT` (default 3001). Gated by IP allowlist +
 *      admin API-key auth.
 *
 * Why two apps in one process:
 *   * The public listener must NOT be reachable from the same
 *     middleware chain as the admin listener — IP allowlist applies
 *     to admin, NOT to public auth.
 *   * A crash in admin code can't take down public auth.
 *   * Different logger channels (public vs admin) keep the audit
 *     stream clean.
 *
 * If either app fails to bind its port, the process exits 1 with a
 * clear error. If EITHER app throws during startup, we tear down
 * the other before exiting.
 *
 * Fatal-error policy (audit 2026-10-19): `uncaughtException` and
 * `unhandledRejection` log via pino (when the logger is up), drain
 * both apps with a 2s cap, and exit 1. The process is NOT kept alive
 * after a fatal error — Node/Nest guidance is terminate + restart;
 * a corrupted auth process must not keep serving.
 */
async function bootstrap(): Promise<void> {
  // App refs for the fatal-error path. Populated as soon as each
  // app boots; either may still be null if we crash mid-startup.
  let publicApp: INestApplication | null = null;
  let adminApp: INestApplication | null = null;
  let pinoLogger: PinoLogger | null = null;
  let shuttingDown = false;

  const fatal = (kind: string, err: unknown): void => {
    // Guard against a second fatal arriving mid-shutdown.
    if (shuttingDown) return;
    shuttingDown = true;
    const detail =
      err instanceof Error ? (err.stack ?? err.message) : String(err);
    if (pinoLogger) {
      pinoLogger.error(`[${kind}] ${detail}`);
    } else {
      console.error(`[${kind}]`, detail);
    }
    const closeWithDrain = async (app: INestApplication): Promise<unknown> => {
      const close = app.close();
      // 2s drain cap: never hang the exit on a stuck connection.
      return await Promise.race([
        close,
        new Promise((resolve) =>
          setTimeout(() => resolve('drain-timeout'), 2_000),
        ),
      ]);
    };
    Promise.allSettled(
      [publicApp, adminApp]
        .filter((a): a is INestApplication => a !== null)
        .map(closeWithDrain),
    )
      .catch(() => undefined)
      .finally(() => {
        process.exit(1);
      });
  };

  process.on('uncaughtException', (err) => {
    fatal('uncaughtException', err);
  });
  process.on('unhandledRejection', (err) => {
    fatal('unhandledRejection', err);
  });

  // Boot both apps in parallel. The order matters only for error
  // reporting — neither depends on the other at runtime.
  [publicApp, adminApp] = await Promise.all([
    bootstrapPublicApp(),
    bootstrapAdminApp(),
  ]);

  // Pull ports from the public app's ConfigService (already loaded
  // with env + validation). A standalone `new ConfigService()` would
  // have no values.
  const publicConfig = publicApp.get(ConfigService);
  const publicPort = publicConfig.getOrThrow<AppConfig['port']>('port');
  const adminPort =
    publicConfig.getOrThrow<AppConfig['adminPort']>('adminPort');

  await Promise.all([publicApp.listen(publicPort), adminApp.listen(adminPort)]);

  const publicLogger = publicApp.get(PinoLogger);
  pinoLogger = publicLogger;
  publicLogger.log(
    `cerberus public  listening on :${publicPort} (NODE_ENV=${process.env.NODE_ENV ?? 'development'})`,
  );
  adminApp
    .get(PinoLogger)
    .log(
      `cerberus admin   listening on :${adminPort} (NODE_ENV=${process.env.NODE_ENV ?? 'development'})`,
    );

  // Drain in-flight requests on SIGTERM/SIGINT.
  publicApp.enableShutdownHooks();
  adminApp.enableShutdownHooks();
}

bootstrap().catch((err: unknown) => {
  console.error('[bootstrap] fatal error', err);
  process.exit(1);
});
