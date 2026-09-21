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
  // route (REST + GraphQL + JWKS) keeps the security headers.
  const apiDocsPathPrefix = '/api-docs';
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith(apiDocsPathPrefix)) {
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

void GraphqlDomainErrorFilter;
