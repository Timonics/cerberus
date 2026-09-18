import 'reflect-metadata';
import { RequestMethod, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Logger as PinoLogger } from 'nestjs-pino';
import helmet from 'helmet';
import { AppModule } from './app.module';

/**
 * Application bootstrap.
 *
 * Order of operations is intentional:
 *
 *   1. `bufferLogs: true` — buffer log lines until we've installed our Pino
 *      logger, so we don't get unsightly Nest-internal default logs.
 *   2. `abortOnError: true` — any module-construction failure (missing env
 *      var, bad config, etc.) should crash the process loudly. Better to
 *      fail at boot than to serve broken requests.
 *   3. Install the Pino logger, flush buffered logs.
 *   4. Hardening middleware: helmet (security headers), CORS off by default
 *      (this is a backend-to-backend service, not a browser surface).
 *   5. ValidationPipe globally — runs class-validator on every @Body()
 *      DTO. Rejects unknown fields so a future schema change doesn't
 *      silently swallow extra payload fields.
 *   6. Shutdown hooks — ensure SIGTERM drains in-flight requests before the
 *      process exits.
 *   7. Route prefix — all API routes are versioned under `/v1`. Health,
 *      readiness, and JWKS are intentionally unversioned.
 */
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    abortOnError: true,
  });

  app.useLogger(app.get(PinoLogger));
  app.flushLogs();

  // Backend-to-backend service; no browser CORS surface in V1.
  app.use(helmet());
  app.enableCors({ origin: false });

  // Run class-validator on every DTO. `whitelist: true` drops unknown
  // fields so extra payload keys can't smuggle data past the schema.
  // `forbidNonWhitelisted: true` makes that rejection loud.
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Drain in-flight requests on SIGTERM/SIGINT.
  app.enableShutdownHooks();

  // All API routes are versioned under /v1. Health, readiness, and the JWKS
  // document are intentionally unversioned so orchestrators and resource
  // servers can find them at conventional paths.
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'health', method: RequestMethod.GET },
      { path: 'ready', method: RequestMethod.GET },
      { path: '.well-known/jwks.json', method: RequestMethod.GET },
    ],
  });

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);

  app
    .get(PinoLogger)
    .log(
      `cerberus listening on :${port} (NODE_ENV=${process.env.NODE_ENV ?? 'development'})`,
    );
}

bootstrap().catch((err: unknown) => {
  // The Nest logger is not up yet at this point, so log directly to stderr
  // and exit non-zero. Boot failures must be loud, never silent.

  console.error('[bootstrap] fatal error', err);
  process.exit(1);
});
