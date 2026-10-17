/**
 * Test-only copy of AppModule — same DI graph minus HealthModule.
 *
 * HealthModule imports @nestjs/terminus, which is ESM-only at the
 * version pinned by package.json. ts-jest can't load ESM modules
 * from node_modules under the default transform pipeline, so any
 * test that boots the full AppModule fails with "Must use import to
 * load ES Module".
 *
 * This module is the production AppModule's import list, dropped
 * one row. Use it in integration tests that need HTTP/GraphQL
 * (controllers, guards, resolvers) but don't need the readiness
 * probe endpoints.
 */

import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';
import { configuration } from '../src/config/configuration';
import { envValidationSchema } from '../src/config/env.validation';
import { SharedKernelModule } from '../src/shared/shared-kernel.module';
import { AppLoggerModule } from '../src/common/logger/app-logger.module';
import { PrismaModule } from '../src/prisma/prisma.module';
import { RedisModule } from '../src/redis/redis.module';
import { IdentityModule } from '../src/identity/identity.module';
import { AuthenticationModule } from '../src/authentication/authentication.module';
import { AuthorizationModule } from '../src/authorization/authorization.module';
import { EngagementModule } from '../src/engagement/engagement.module';
import { AppsModule } from '../src/apps/apps.module';
import { GraphqlModule } from '../src/graphql/graphql.module';
import { AdminModule } from '../src/administration/administration.module';
import { CleanupModule } from '../src/cleanup/cleanup.module';
import { DomainErrorFilter } from '../src/shared/interfaces/domain-error.filter';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';

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
    AdminModule,
    GraphqlModule,
    CleanupModule,
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: DomainErrorFilter,
    },
    {
      // The GraphQL filter was previously imported but never registered
      // (commit d7546b3). Tests should register it explicitly so
      // resolvers' DomainErrors surface their extensions.code via the
      // GraphqlDomainErrorFilter instead of getting wrapped in
      // INTERNAL_SERVER_ERROR.
      provide: APP_FILTER,
      useClass: GraphqlDomainErrorFilter,
    },
  ],
})
export class PublicTestModule {}
