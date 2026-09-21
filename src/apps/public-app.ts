import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { RequestMethod } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { apiReference } from '@scalar/nestjs-api-reference';
import { AppModule } from '../app.module';
import { GraphqlDomainErrorFilter } from '../graphql/graphql-domain-error.filter';

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

  app.use(helmet());
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

  // Scalar API reference. Reads the OpenAPI 3.1 spec from disk
  // (copied to dist/ at build time by scripts/copy-openapi.js).
  // V1.5 uses bearer JWT — pre-fill the auth UI so "Authorize" works
  // out of the box.
  app.use(
    '/api-docs',
    apiReference({
      spec: {
        content: readFileSync(
          join(process.cwd(), 'dist', 'openapi.yaml'),
          'utf8',
        ),
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
