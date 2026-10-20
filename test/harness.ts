/**
 * Minimal Nest testing harness — boots only the modules the
 * integration tests need (Prisma + the session refresh use-case),
 * not the entire AppModule. This sidesteps the ESM-load-time
 * cascade through the full DI graph (HealthModule, GraphQLModule,
 * Scalar docs) and keeps the test setup fast and stable.
 *
 * Use this for tests that exercise:
 *   - SessionRepository (refresh-rotation, reuse detection)
 *   - RefreshSessionUseCase (H-1 atomic rotation)
 *   - RefreshTokenGrantUseCase (C-4 mfaRequired)
 *   - VerifySecondFactorUseCase (C-4 mfaVerified marking)
 *   - AdminDisableUserMfaUseCase (C-1 cross-tenant IDOR)
 *
 * For HTTP-level tests (controllers, guards, middleware) use
 * `supertest` + the AppModule — those need a real listener.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { AppLoggerModule } from '../src/common/logger/app-logger.module';
import { PrismaModule } from '../src/prisma/prisma.module';
import { RedisModule } from '../src/redis/redis.module';
import { SharedKernelModule } from '../src/shared/shared-kernel.module';
import { IdentityModule } from '../src/identity/identity.module';
import { AuthenticationModule } from '../src/authentication/authentication.module';
import { AuthorizationModule } from '../src/authorization/authorization.module';
import { EngagementModule } from '../src/engagement/engagement.module';
import { configuration } from '../src/config/configuration';
import { envValidationSchema } from '../src/config/env.validation';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

let _prisma: PrismaClient | undefined;
let _redis: Redis | undefined;

export function getPrisma(): PrismaClient {
  if (!_prisma) {
    _prisma = new PrismaClient({
      datasources: {
        db: {
          url:
            process.env.DATABASE_URL ??
            'postgresql://cerberus:cerberus@localhost:5434/cerberus',
        },
      },
    });
  }
  return _prisma;
}

export function getRedis(): Redis {
  if (!_redis) {
    _redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6384', {
      lazyConnect: false,
      maxRetriesPerRequest: 3,
    });
  }
  return _redis;
}

export async function resetRateLimits(): Promise<void> {
  const redis = getRedis();
  // Must match the ThrottleGuard key prefix (`throttle:ip:…`,
  // `throttle:email:…`, `throttle:user:…`) — the shared Redis-backed
  // counters otherwise leak across suites and runs.
  const keys = await redis.keys('throttle:*');
  if (keys.length > 0) await redis.del(...keys);
}

/**
 * Build the minimal Nest DI context for integration tests. Includes
 * the bounded-context modules that own the use-cases under test
 * (Identity, Authentication, Authorization, Engagement) plus the
 * shared kernel (Prisma, Redis, Config, Logger).
 */
export async function buildIntegrationContext(): Promise<TestingModule> {
  await resetRateLimits();
  return Test.createTestingModule({
    imports: [
      // Config is global; the production app uses ConfigModule.forRoot.
      // We replicate the minimal config here so ConfigService is
      // resolvable from any module in this test graph.
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
    ],
  }).compile();
}

/**
 * Generate a unique email. The `users.email` UNIQUE constraint
 * means tests can't share emails — each test creates a new one.
 */
export function uniqueEmail(prefix = 'e2e'): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@cerberus.test`;
}

export async function teardown(): Promise<void> {
  if (_prisma) {
    try {
      await _prisma.$disconnect();
    } catch {
      // ignore — connection may already be closed
    }
  }
  if (_redis) {
    try {
      // ioredis 5 throws on quit() if the connection is already closed.
      // disconnect() is gentler and never throws.
      _redis.disconnect();
    } catch {
      // ignore
    }
  }
  _prisma = undefined;
  _redis = undefined;
}
