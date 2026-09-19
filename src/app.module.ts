import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { configuration } from './config/configuration';
import { envValidationSchema } from './config/env.validation';
import { SharedKernelModule } from './shared/shared-kernel.module';
import { AppLoggerModule } from './common/logger/app-logger.module';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { HealthModule } from './health/health.module';
import { IdentityModule } from './identity/identity.module';
import { AuthenticationModule } from './authentication/authentication.module';
import { AuthorizationModule } from './authorization/authorization.module';
import { EngagementModule } from './engagement/engagement.module';
import { AppsModule } from './apps/apps.module';
import { GraphqlModule } from './graphql/graphql.module';
import { DomainErrorFilter } from './shared/interfaces/domain-error.filter';

/**
 * Root application module.
 *
 * Composition order matters in Nest:
 *
 *   1. ConfigModule first — every downstream module reads from ConfigService.
 *   2. SharedKernelModule (global) — Clock / EventBus / IdGenerator /
 *      TransactionRunner.
 *   3. AppLoggerModule (global via nestjs-pino's auto-registration).
 *   4. Infra (Prisma, Redis) — global, lifecycle-managed.
 *   5. Bounded contexts — each in its own module.
 *   6. Health module last — depends on the infra modules above.
 *
 * The global DomainErrorFilter maps domain-layer errors to HTTP responses
 * with stable codes (no stack-traces leaking to clients).
 */
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [configuration],
      validationSchema: envValidationSchema,
      envFilePath: ['.env.local', '.env'],
    }),
    SharedKernelModule,
    AppLoggerModule,
    PrismaModule,
    RedisModule,
    IdentityModule,
    AuthenticationModule,
    AuthorizationModule,
    EngagementModule,
    AppsModule,
    GraphqlModule,
    HealthModule,
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: DomainErrorFilter,
    },
  ],
})
export class AppModule {}
