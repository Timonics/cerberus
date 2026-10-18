import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { RequestMethod } from '@nestjs/common';
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
import { AppModule } from '../app.module';
import { GraphqlDomainErrorFilter } from '../graphql/graphql-domain-error.filter';
import { readArtifact } from '../common/artifact-loader';
import { AppConfig } from '../config/configuration';

/**
 * Bootstrap the public-facing NestApplication.
 *
 * Mounts: `/health`, `/ready`, `/.well-known/jwks.json`, all `/v1/*`
 * routes (identity / auth / OAuth / engagement), `/graphql`, and the
 * Scalar API reference at `/api-docs`.
 *
 * Listens on `PORT` (default 3000).
 */
export async function bootstrapPublicApp(): Promise<INestApplication> {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    abortOnError: true,
  });
  app.useLogger(app.get(PinoLogger));
  app.flushLogs();

  // V1.5: HTTP hardening. The defaults (100 KiB body, 30s timeouts)
  // are read from config so operators can tune per-environment.
  const httpCfg = app.get(ConfigService).getOrThrow<AppConfig['http']>('http');
  // Reject oversized request bodies BEFORE the JSON parser spends
  // memory allocating them. Express 5's body-parser returns 413
  // automatically when the limit is exceeded.
  app.use(json({ limit: httpCfg.bodyLimitBytes }));
  app.use(urlencoded({ limit: httpCfg.bodyLimitBytes, extended: true }));
  // V1.7 audit fix #12: trust the X-Forwarded-* headers from a
  // known number of upstream proxies. Without this, `req.ip` (used
  // by the ThrottleGuard, the LoginUseCase lockout key, and the
  // IpAllowlistGuard for the admin listener) is the direct socket
  // address — which behind an L7 load balancer is always the LB's
  // IP. Default 1 hop (works for AWS ALB / nginx / Cloudflare).
  // Set TRUST_PROXY_HOPS=0 to disable (direct connections only).
  // V1.7 audit fix #12: INestApplication doesn't expose `set()`,
  // but the underlying Express instance does. We access it via
  // getHttpAdapter().getInstance() (Nest 9+ API).
  (app.getHttpAdapter().getInstance() as ExpressApplication).set(
    'trust proxy',
    httpCfg.trustProxyHops,
  );
  // Hard timeouts on the request and response phases. Without
  // these, a malicious client can hold a connection open
  // indefinitely, exhausting the server's connection pool.
  const server = app.getHttpServer() as HttpServer;
  if (server && typeof server.setTimeout === 'function') {
    server.setTimeout(httpCfg.requestTimeoutMs);
  }
  // Express also exposes a per-request response timeout via
  // res.setTimeout(). We apply it as a default for every request
  // by attaching it to the response object inside a tiny middleware.
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

  // helmet applies strict defaults (CSP, X-Frame-Options, etc.) that
  // block Scalar's inline scripts and CDN-fetched assets at /api-docs.
  // Apply helmet only to paths that are NOT the API docs — every other
  // route (REST + GraphQL + JWKS) keeps the security headers. We also
  // explicitly remove any CSP-related headers that may have leaked from
  // earlier middleware, since browser cache can pin a stale response.
  const apiDocsPathPrefix = '/api-docs';
  const isApiDocsPath = (path: string): boolean =>
    path === apiDocsPathPrefix || path.startsWith(`${apiDocsPathPrefix}/`);
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (isApiDocsPath(req.path)) {
      res.removeHeader('Content-Security-Policy');
      res.removeHeader('Content-Security-Policy-Report-Only');
      res.removeHeader('Cross-Origin-Embedder-Policy');
      res.removeHeader('Cross-Origin-Opener-Policy');
      res.removeHeader('Cross-Origin-Resource-Policy');
      return next();
    }
    return helmet()(req, res, next);
  });
  app.enableCors({ origin: false });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      // V1.5 (audit L-3): reject unknown body fields. The previous
      // setting silently dropped them, which hides contract drift
      // (e.g. a client typo `passwrod` instead of `password` would
      // result in an empty string and a confusing "invalid password"
      // error instead of "unknown field"). GraphQL inputs bypass
      // this pipe via their own @Args() binding so the change is
      // REST-only.
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // V1.5 (audit L-5 follow-on): register the GraphQL domain-error
  // filter so DomainError.code surfaces as `extensions.code` on the
  // GraphQL response — without this, resolvers' DomainErrors get
  // wrapped in INTERNAL_SERVER_ERROR and the `domainCode` is lost.
  app.useGlobalFilters(new GraphqlDomainErrorFilter());

  // Routes are versioned under /v1. Health, readiness, JWKS, Scalar,
  // and GraphQL are intentionally unversioned.
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'ready', method: RequestMethod.GET },
      { path: '.well-known/jwks.json', method: RequestMethod.GET },
    ],
  });

  // Scalar API reference. `readArtifact` prefers `dist/openapi.yaml`
  // (production path; copied at build time by scripts/copy-openapi.js)
  // and falls back to `src/openapi.yaml` for `npm run start:dev` —
  // `nest start --watch` wipes `dist/` on every rebuild mid-session.
  app.use(
    '/api-docs',
    apiReference({
      spec: {
        content: readArtifact('openapi.yaml'),
        title: 'Cerberus Authentication API',
      },
      meta: {
        title: 'Cerberus API Reference',
      },
      authentication: {
        preferredSecurityScheme: 'bearerAuth',
        securitySchemePersistent: true,
      },
    }),
  );

  return app;
}
