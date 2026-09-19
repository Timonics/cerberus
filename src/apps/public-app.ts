import { INestApplication, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { RequestMethod } from '@nestjs/common';
import { AppModule } from '../app.module';
import { GraphqlDomainErrorFilter } from '../graphql/graphql-domain-error.filter';

/**
 * Bootstrap the public-facing NestApplication.
 *
 * Mounts: `/health`, `/ready`, `/.well-known/jwks.json`, all `/v1/*`
 * routes (identity / auth / OAuth / engagement), and `/graphql`.
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

  // Routes are versioned under /v1. Health, readiness, JWKS, and
  // GraphQL are intentionally unversioned.
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'ready', method: RequestMethod.GET },
      { path: '.well-known/jwks.json', method: RequestMethod.GET },
    ],
  });

  return app;
}

void GraphqlDomainErrorFilter;
