import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { json, urlencoded } from 'express';
import type {
  Request,
  Response,
  NextFunction,
  Application as ExpressApplication,
} from 'express';
import type { Server as HttpServer } from 'node:http';
import { apiReference } from '@scalar/nestjs-api-reference';
import { ConfigService } from '@nestjs/config';
import { AdminModule } from '../administration/administration.module';
import { readArtifact } from '../common/artifact-loader';
import { AppConfig } from '../config/configuration';

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

  // V1.5: HTTP hardening (mirrors public-app.ts). The admin
  // surface is IP-allowlisted at the route layer so the body
  // limit + timeouts are belt-and-suspenders.
  const httpCfg = app.get(ConfigService).getOrThrow<AppConfig['http']>('http');
  app.use(json({ limit: httpCfg.bodyLimitBytes }));
  app.use(urlencoded({ limit: httpCfg.bodyLimitBytes, extended: true }));
  // V1.7 audit fix #12 + audit 2026-10-19 H-11: the ADMIN listener has
  // its OWN trust-proxy knob (`adminTrustProxyHops`, default 0). The
  // public listener's default of 1 must NOT apply here: if the admin
  // port is directly reachable, trusting XFF lets any client spoof
  // `X-Forwarded-For: 127.0.0.1` and walk past the IpAllowlistGuard.
  // Set ADMIN_TRUST_PROXY_HOPS explicitly when a real reverse proxy
  // sits in front of the admin port.
  (app.getHttpAdapter().getInstance() as ExpressApplication).set(
    'trust proxy',
    httpCfg.adminTrustProxyHops,
  );
  const server = app.getHttpServer() as HttpServer;
  if (server && typeof server.setTimeout === 'function') {
    server.setTimeout(httpCfg.requestTimeoutMs);
  }
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setTimeout(httpCfg.responseTimeoutMs, () => {
      if (!res.headersSent) {
        res.status(503).end('Request timed out');
      } else {
        res.destroy();
      }
    });
    next();
  });

  // Audit 2026-10-19 (helmet on docs paths): /admin/docs gets helmet
  // with CSP + COEP disabled (Scalar's UI needs inline scripts and CDN
  // assets); every other admin route gets the strict defaults. The docs
  // path is NO LONGER helmet-free — only its CSP/COEP are relaxed.
  const relaxedHelmet = helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  });
  app.use((req: Request, res: Response, next: NextFunction) => {
    const isDocsPath =
      req.path === '/admin/docs' || req.path.startsWith('/admin/docs/');
    return isDocsPath
      ? relaxedHelmet(req, res, next)
      : helmet()(req, res, next);
  });
  app.enableCors({ origin: false });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      // V1.5 (audit L-3): see public-app.ts. REST-only change.
      forbidNonWhitelisted: true,
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
