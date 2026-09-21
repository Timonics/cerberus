import { Global, Module } from '@nestjs/common';
import { AppLoggerModule } from '../common/logger/app-logger.module';
import { PrismaModule } from '../prisma/prisma.module';
import { SharedKernelModule } from '../shared/shared-kernel.module';
import { RedisModule } from '../redis/redis.module';
import { ConfigModule } from '@nestjs/config';
import { configuration } from '../config/configuration';
import { envValidationSchema } from '../config/env.validation';
import { DomainErrorFilter } from '../shared/interfaces/domain-error.filter';
import { APP_FILTER } from '@nestjs/core';
import { RegisterAppUseCase } from './application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from './application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from './application/use-cases/revoke-app.use-case';
import { VerifyAppApiKeyUseCase } from './application/use-cases/verify-app-api-key.use-case';
import { AppsGraphqlResolver } from './interfaces/graphql/apps.resolver';
import {
  Argon2AppApiKeyHasher,
  APP_API_KEY_HASHER,
} from './infrastructure/security/argon2-app-api-key.hasher';
import { PrismaAppRepository } from './infrastructure/persistence/prisma-app.repository';
import { APP_REPOSITORY } from './domain/ports/app.repository.port';
import { AppsController } from './interfaces/http/apps.controller';

/**
 * Apps bounded context — Nest wiring.
 *
 * Marks itself `@Global()` so the IdentityModule can inject
 * `VerifyAppApiKeyUseCase` directly without re-importing the apps
 * module — that lets register-time org-binding see app credentials
 * with no extra wiring in IdentityModule.
 *
 * Mounted on the PUBLIC listener (port 3000) alongside `/v1/identity/*`
 * and `/v1/auth/*`. Apps are end-user-facing (third-party devs
 * register their apps against the public surface) so they belong
 * here, not on the admin listener.
 */
@Global()
@Module({
  imports: [
    AppLoggerModule,
    // ConfigModule must mirror the public app's setup so ConfigService
    // has access to env-loaded values.
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [configuration],
      validationSchema: envValidationSchema,
      envFilePath: ['.env.local', '.env'],
    }),
    PrismaModule,
    RedisModule,
    SharedKernelModule,
  ],
  controllers: [AppsController],
  providers: [
    // Infrastructure
    PrismaAppRepository,
    Argon2AppApiKeyHasher,
    {
      provide: APP_REPOSITORY,
      useClass: PrismaAppRepository,
    },
    {
      provide: APP_API_KEY_HASHER,
      useExisting: Argon2AppApiKeyHasher,
    },

    // Use-cases
    RegisterAppUseCase,
    RotateAppApiKeyUseCase,
    RevokeAppUseCase,
    VerifyAppApiKeyUseCase,

    // GraphQL resolver (V1.5)
    AppsGraphqlResolver,

    // Global error filter for the apps endpoints (REST context).
    {
      provide: APP_FILTER,
      useClass: DomainErrorFilter,
    },
  ],
  exports: [
    Argon2AppApiKeyHasher,
    APP_API_KEY_HASHER,
    RegisterAppUseCase,
    RotateAppApiKeyUseCase,
    RevokeAppUseCase,
    VerifyAppApiKeyUseCase,
  ],
})
export class AppsModule {}
