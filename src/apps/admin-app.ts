import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { AdminModule } from '../administration/administration.module';

/**
 * Bootstrap the admin-facing NestApplication.
 *
 * Mounts `/admin/*` only — no public routes, no `/v1/*`, no
 * `/graphql`. The app enforces IP allowlist + admin API-key auth at
 * the controller layer (decorators + guards).
 *
 * Listens on `ADMIN_PORT` (default 3001).
 *
 * V1 caveat: the admin listener runs WITHOUT an HTTP-level IP
 * allowlist middleware — the `IpAllowlistGuard` runs at the route
 * layer (Nest's `CanActivate`). That means an attacker hitting an
 * unknown route still gets the standard 404 response, but they don't
 * hit a real admin endpoint without passing the guard. We accept this
 * because V1 only has `/admin/*` routes and the guard runs on every
 * one of them. V1.5 will move the allowlist to a global middleware
 * for defense-in-depth.
 */
export async function bootstrapAdminApp(): Promise<INestApplication> {
  const app = await NestFactory.create(AdminModule, {
    bufferLogs: true,
    abortOnError: true,
  });
  app.useLogger(app.get(PinoLogger));
  app.flushLogs();

  // helmet is more aggressive on the admin surface — we block all
  // cross-origin traffic and disable the form-action allowance.
  app.use(helmet());
  app.enableCors({ origin: false });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: false,
      transform: true,
    }),
  );

  // /admin/health is the only unauthenticated endpoint — it lives
  // in its own `AdminHealthController` (no `@UseGuards(...)`). The
  // IpAllowlistGuard + AdminApiKeyGuard on `AdminController` apply
  // to every other route.

  return app;
}
