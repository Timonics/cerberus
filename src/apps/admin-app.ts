import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import type { Request, Response, NextFunction } from 'express';
import { apiReference } from '@scalar/nestjs-api-reference';
import { AdminModule } from '../administration/administration.module';
import { readArtifact } from '../common/artifact-loader';

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

  // Skip helmet on /admin/docs (Scalar UI), same as the public app.
  // helmet's strict CSP blocks Scalar's inline scripts and CDN assets.
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/admin/docs')) {
      return next();
    }
    return helmet()(req, res, next);
  });
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

  // Scalar API reference at /admin/docs. `readArtifact` prefers
  // dist/openapi-admin.yaml (prod) and falls back to src/ for
  // `npm run start:dev`. The admin OpenAPI spec is intentionally
  // SEPARATE from the public spec — operators hitting /admin/docs
  // see only the IP-allowlisted admin surface, not the public
  // auth endpoints.
  app.use(
    '/admin/docs',
    apiReference({
      spec: {
        content: readArtifact('openapi-admin.yaml'),
        title: 'Cerberus Administration API',
      },
      meta: {
        title: 'Cerberus Admin API Reference',
      },
      authentication: {
        preferredSecurityScheme: 'adminApiKey',
        securitySchemePersistent: true,
      },
    }),
  );

  return app;
}
