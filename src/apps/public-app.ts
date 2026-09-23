import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { RequestMethod } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { apiReference } from '@scalar/nestjs-api-reference';
import { AppModule } from '../app.module';
import { GraphqlDomainErrorFilter } from '../graphql/graphql-domain-error.filter';
import { readArtifact } from '../common/artifact-loader';

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
