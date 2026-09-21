import { Global, Module } from '@nestjs/common';
import { AppLoggerModule } from '../common/logger/app-logger.module';
import { PrismaModule } from '../prisma/prisma.module';
import { IdentityModule } from '../identity/identity.module';
import { AuthenticationModule } from '../authentication/authentication.module';
import { EngagementModule } from '../engagement/engagement.module';
import { SharedKernelModule } from '../shared/shared-kernel.module';
import { RedisModule } from '../redis/redis.module';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER } from '@nestjs/core';
import { configuration } from '../config/configuration';
import { envValidationSchema } from '../config/env.validation';
import { DomainErrorFilter } from '../shared/interfaces/domain-error.filter';
import { IssueAdminApiKeyUseCase } from './application/use-cases/issue-admin-api-key.use-case';
import { RevokeAdminApiKeyUseCase } from './application/use-cases/revoke-admin-api-key.use-case';
import { VerifyAdminApiKeyUseCase } from './application/use-cases/verify-admin-api-key.use-case';
import { AdminDisableUserMfaUseCase } from './application/use-cases/admin-disable-user-mfa.use-case';
import { AdminSearchAuditLogUseCase } from './application/use-cases/admin-search-audit-log.use-case';
import {
  ADMIN_API_KEY_HASHER,
  AdminApiKeyHasher,
} from './infrastructure/security/argon2-admin-api-key.hasher';
import { PrismaAdminApiKeyRepository } from './infrastructure/persistence/prisma-admin-api-key.repository';
import { AdminApiKeyLookupTokenService } from './infrastructure/security/admin-api-key-lookup-token.service';
import { ADMIN_API_KEY_REPOSITORY } from './domain/ports/admin-api-key.repository.port';
import { AdminController } from './interfaces/http/admin.controller';
import { AdminHealthController } from './interfaces/http/admin-health.controller';
import { AdminApiKeyGuard } from './interfaces/security/admin-api-key.guard';
import { AdminGraphqlResolver } from './interfaces/graphql/admin.resolver';
import { IpAllowlistGuard } from './interfaces/security/ip-allowlist.guard';
import { OAuthAdminController } from './interfaces/http/oauth-admin.controller';

/**
 * Token used to inject the parsed IP allowlist into `IpAllowlistGuard`.
 * The guard needs the parsed value at construction time; we wrap it
 * in a provider token so the bootstrap can pass it from config.
 */
export const ADMIN_IP_ALLOWLIST = Symbol('ADMIN_IP_ALLOWLIST');

/**
 * Administration bounded context — Nest wiring.
 *
 * Bootstrapped as a SEPARATE NestApplication in `main.ts` on a
 * different port (default 3001) from the public surface. Each app
 * has its own DI container; the Prisma client is re-instantiated
 * per app (cheap — actual TCP-level pool sharing happens at the
 * Postgres server, not in-process). Keeping them separate gives us:
 *   1. Isolation: a fatal crash in admin code can't take down public
 *      auth.
 *   2. Clean logs: admin actions stay on a separate logger channel.
 *   3. Independent lifecycle: admin can be restarted without
 *      dropping public sessions.
 *   4. Defense in depth: even if the public app is compromised, the
 *      admin listener isn't reachable from the same process.
 *
 * Routes mounted (no prefix — admin context is its own listener):
 *   GET  /admin/health
 *   POST /admin/api-keys
 *   GET  /admin/api-keys
 *   DELETE /admin/api-keys/:id
 *   GET  /admin/users/:id
 *   POST /admin/users/:id/disable-mfa
 *   GET  /admin/audit-log
 *
 * Cross-context deps (re-imported from the public app):
 *   * `IdentityModule` — for `GetUserUseCase` (admin getUser).
 *   * `EngagementModule` — for the audit log repository.
 *   * `AuthenticationModule` — for `MfaSecretRepository` (admin MFA disable).
 */
@Global()
@Module({
  imports: [
    AppLoggerModule,
    // ConfigModule must mirror the public app's setup so ConfigService
    // has access to env-loaded values (`nodeEnv`, `port`, etc.) and
    // can validate the same env. We re-`forRoot({...})` because each
    // NestApplication needs its own ConfigModule instance.
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
    IdentityModule,
    AuthenticationModule,
    EngagementModule,
  ],
  controllers: [AdminController, AdminHealthController, OAuthAdminController],
  providers: [
    // Infrastructure
    PrismaAdminApiKeyRepository,
    AdminApiKeyHasher,
    AdminApiKeyLookupTokenService,
    {
      provide: ADMIN_API_KEY_REPOSITORY,
      useClass: PrismaAdminApiKeyRepository,
    },
    {
      provide: ADMIN_API_KEY_HASHER,
      useExisting: AdminApiKeyHasher,
    },

    // Allowlist + admin-key guards. The allowlist guard self-reads
    // its config from `ConfigService` via constructor injection, so
    // it can be instantiated like any other `@Injectable()`.
    IpAllowlistGuard,
    AdminApiKeyGuard,

    // Use-cases
    IssueAdminApiKeyUseCase,
    RevokeAdminApiKeyUseCase,
    VerifyAdminApiKeyUseCase,
    AdminDisableUserMfaUseCase,
    AdminSearchAuditLogUseCase,

    // GraphQL resolver (V1.5) — exposed via the public app's
    // `/graphql` endpoint with `org:admin` scope requirement. The
    // admin REST listener (port 3001) does NOT mount `/graphql` —
    // admin GraphQL is interactive-admin only.
    AdminGraphqlResolver,

    // Global error filter — same as the public app so REST + GraphQL
    // (if added later) return stable error codes.
    {
      provide: APP_FILTER,
      useClass: DomainErrorFilter,
    },
  ],
  exports: [
    AdminApiKeyHasher,
    ADMIN_API_KEY_HASHER,
    ADMIN_API_KEY_REPOSITORY,
    AdminGraphqlResolver,
  ],
})
export class AdminModule {}
