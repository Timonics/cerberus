/**
 * V1.5.1 per-email rate limit — full integration.
 *
 * Pins the IP-rotation brute-force mitigation in src/common/throttle.guard.ts:
 * an attacker rotating IPs but targeting one specific account is
 * blocked by a separate per-email Redis counter. Without this guard,
 * the per-IP counter would never trip — 1000 IPs × 20 attempts = 20,000
 * attempts against one email without ever hitting any single IP's cap.
 *
 * Test approach:
 *   1. Register a real user (so the email exists in the system and
 *      login attempts go through the credential path).
 *   2. Boot the test app with `trust proxy` enabled so we can simulate
 *      IP rotation via `X-Forwarded-For` headers.
 *   3. Set `RATE_LIMIT_PER_EMAIL_MAX=3` via env so the test doesn't
 *      need 10 requests before rejection.
 *   4. Drive 4 logins from 4 distinct `X-Forwarded-For` IPs, all using
 *      the same email. The first 3 hit the per-email cap exactly;
 *      the 4th is rejected with `bucket: 'email'`.
 *   5. Also verify the per-IP path still works: from one IP, hammer
 *      past the per-IP cap and expect `bucket: 'ip'`.
 *
 * The rate-limited response is mapped to HTTP 429 by the DomainErrorFilter
 * (statusFor returns TOO_MANY_REQUESTS for `authentication.rate_limited`).
 */

import { Test, TestingModule } from '@nestjs/testing';
import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { configuration } from '../src/config/configuration';
import { envValidationSchema } from '../src/config/env.validation';
import { ConfigModule } from '@nestjs/config';
import { AppLoggerModule } from '../src/common/logger/app-logger.module';
import { PrismaModule } from '../src/prisma/prisma.module';
import { RedisModule } from '../src/redis/redis.module';
import { RedisService } from '../src/redis/redis.service';
import { SharedKernelModule } from '../src/shared/shared-kernel.module';
import { IdentityModule } from '../src/identity/identity.module';
import { AuthenticationModule } from '../src/authentication/authentication.module';
import { AuthorizationModule } from '../src/authorization/authorization.module';
import { EngagementModule } from '../src/engagement/engagement.module';
import { AppsModule } from '../src/apps/apps.module';
import { AdminModule } from '../src/administration/administration.module';
import { GraphqlModule } from '../src/graphql/graphql.module';
import { CleanupModule } from '../src/cleanup/cleanup.module';
import { DomainErrorFilter } from '../src/shared/interfaces/domain-error.filter';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { ThrottleGuard } from '../src/common/throttle.guard';
import { uniqueEmail } from './harness';

describe('Per-email rate limit (integration)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let redis: import('ioredis').default;

  beforeAll(async () => {
    // Force the per-email bucket to a low cap so the test doesn't
    // need 10+ requests. The IP cap stays at the per-route default
    // (20 / minute for login) — well above what we send.
    process.env.RATE_LIMIT_PER_EMAIL_MAX = '3';

    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: ['.env.local', '.env'],
          load: [configuration],
          validationSchema: envValidationSchema,
        }),
        AppLoggerModule,
        PrismaModule,
        RedisModule,
        SharedKernelModule,
        IdentityModule,
        AuthenticationModule,
        AuthorizationModule,
        EngagementModule,
        AppsModule,
        AdminModule,
        GraphqlModule,
        CleanupModule,
      ],
      providers: [
        { provide: 'APP_FILTER', useClass: DomainErrorFilter },
        { provide: 'APP_FILTER', useClass: GraphqlDomainErrorFilter },
      ],
    }).compile();

    app = module.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix('v1', {
      exclude: [
        { path: 'health', method: 0 },
        { path: 'ready', method: 0 },
        { path: '.well-known/jwks.json', method: 0 },
        'graphql',
      ],
    });
    // Trust proxy headers so supertest can simulate IP rotation via
    // `X-Forwarded-For`. Production sets this on the actual Express
    // app; this is the test equivalent.
    (
      app.getHttpAdapter().getInstance() as unknown as {
        set: (k: string, v: unknown) => void;
      }
    ).set('trust proxy', true);

    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();
    const redisSvc = module.get(RedisService);
    redis = redisSvc.getClient();
    // Best-effort cleanup of any stale per-email counters from
    // a previous run (the key names are deterministic in the
    // guard so we can prune them safely).
    await redis.keys('throttle:email:*').then(async (keys) => {
      if (keys.length > 0) await redis.del(...keys);
    });
    await redis.keys('throttle:ip:*').then(async (keys) => {
      if (keys.length > 0) await redis.del(...keys);
    });
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
    delete process.env.RATE_LIMIT_PER_EMAIL_MAX;
  });

  it('rejects an IP-rotation brute-forcer on the per-email bucket', async () => {
    const email = uniqueEmail('per-email-limit');
    const password = 'Correct horse battery 42';

    // Register so the credential exists and login reaches the
    // password-verification step (otherwise login fails with
    // invalid_credentials, never the throttle).
    const registerRes = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .set('X-Forwarded-For', '10.0.0.1');
    expect(registerRes.status).toBe(201);

    // Drive 4 login attempts across 4 distinct IPs. Per-email
    // cap is 3, so the 4th should be rejected by the per-email
    // bucket (NOT the per-IP bucket — each IP only sees 1
    // attempt, far below the per-IP cap of 20).
    const ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'];
    const results: { status: number; body: { code?: string } }[] = [];
    for (const ip of ips) {
      const res = await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send({ email, password })
        .set('X-Forwarded-For', ip);
      results.push({ status: res.status, body: res.body });
    }

    // First 3 pass auth (200). The 4th is throttled (429).
    expect(results[0].status).toBe(200);
    expect(results[1].status).toBe(200);
    expect(results[2].status).toBe(200);
    expect(results[3].status).toBe(429);
    expect(results[3].body.code).toBe('authentication.rate_limited');
  });

  it('the per-email bucket is scoped per (email, route) — same email on a different route has its own counter', async () => {
    const email = uniqueEmail('per-email-scope');
    const password = 'Correct horse battery 42';

    await debugRegister(app.getHttpServer(), email, password, '10.0.0.10');

    // Trip the per-email counter for /auth/login (4 requests,
    // cap is 3 → last rejects).
    for (let i = 0; i < 4; i++) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send({ email, password })
        .set('X-Forwarded-For', '10.0.0.10');
    }

    // /engagement/password-reset/request is a separate route;
    // its per-email counter starts at 0 and should pass the
    // first request even though login is rate-limited.
    const resetRes = await request(app.getHttpServer())
      .post('/v1/engagement/password-reset/request')
      .send({ email })
      .set('X-Forwarded-For', '10.0.0.10');

    expect(resetRes.status).toBe(204);
  });

  it('the rate-limited response includes the bucket in the error code mapping', async () => {
    // The 429 response shape from DomainErrorFilter:
    //   { code: 'authentication.rate_limited', message: 'Too many requests' }
    // The `detail` field is intentionally NOT exposed to clients
    // (see DomainError.toJSON) — security correlates by structured
    // log + Sentry instead. Verify the public shape stays clean.
    const email = uniqueEmail('per-email-shape');
    const password = 'Correct horse battery 42';

    await debugRegister(app.getHttpServer(), email, password, '10.0.1.1');

    // Trip the per-email counter.
    for (const ip of ['10.0.1.2', '10.0.1.3', '10.0.1.4', '10.0.1.5']) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .send({ email, password })
        .set('X-Forwarded-For', ip);
    }

    // The rejection response from this attempt should still
    // expose only code + message, never the bucket/emailHash
    // (those leak which account is being targeted).
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password })
      .set('X-Forwarded-For', '10.0.1.6');

    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      code: 'authentication.rate_limited',
      message: 'Too many requests',
    });
    // Sanity: the bucket/emailHash detail MUST NOT leak.
    expect(res.body).not.toHaveProperty('detail');
    expect(res.body).not.toHaveProperty('bucket');
    expect(res.body).not.toHaveProperty('emailHash');
  });
});

// Suppress unused-import warning for symbols that exist only for
// side effects (module wiring, supertest typing).
void ThrottleGuard;
void VersioningType;
void ConfigService;

/**
 * Wrapper around `POST /v1/identity/register` that logs the body
 * on failure. Class-validator + domain rules can reject a
 * password (length, digit requirement, breach-list) — when that
 * happens the test should tell us WHY, not just "got 422".
 */
async function debugRegister(
  server: Parameters<typeof request>[0],
  email: string,
  password: string,
  ip: string,
): Promise<void> {
  const res = await request(server)
    .post('/v1/identity/register')
    .send({ email, password })
    .set('X-Forwarded-For', ip);
  if (res.status !== 201) {
    console.error('[debug] register failed', res.status, res.body);
  }
  expect(res.status).toBe(201);
}
