import { Global, Module } from '@nestjs/common';
import { ListSessionsUseCase } from './application/use-cases/list-sessions.use-case';
import { LoginUseCase } from './application/use-cases/login.use-case';
import { LogoutUseCase } from './application/use-cases/logout.use-case';
import { RefreshSessionUseCase } from './application/use-cases/refresh-session.use-case';
import { RevokeSessionUseCase } from './application/use-cases/revoke-session.use-case';
import { PasswordChangedSessionRevoker } from './application/event-handlers/password-changed.handler';
import { LockoutPolicy } from './domain/aggregates/lockout-policy';
import { LOGIN_ATTEMPT_REPOSITORY } from './domain/ports/login-attempt.repository.port';
import { SESSION_REPOSITORY } from './domain/ports/session.repository.port';
import { AuthController } from './interfaces/http/auth.controller';
import { PrismaSessionRepository } from './infrastructure/persistence/prisma-session.repository';
import { RedisLoginAttemptRepository } from './infrastructure/persistence/redis-login-attempt.repository';
import {
  REFRESH_TOKEN_GENERATOR,
  RandomRefreshTokenGenerator,
} from './infrastructure/security/refresh-token-generator';

/**
 * Authentication bounded context — Nest wiring.
 *
 * Exports LoginUseCase + SESSION_REPOSITORY for the Authorization
 * context to consume during JWT issuance and refresh-token validation.
 *
 * Marked `@Global()` (V1.5) so the admin app can also import
 * `AuthenticationModule` and reach the session repository without
 * having to re-export every cross-context symbol explicitly.
 */
@Global()
@Module({
  controllers: [AuthController],
  providers: [
    PrismaSessionRepository,
    RedisLoginAttemptRepository,
    RandomRefreshTokenGenerator,
    {
      provide: SESSION_REPOSITORY,
      useClass: PrismaSessionRepository,
    },
    {
      provide: LOGIN_ATTEMPT_REPOSITORY,
      useClass: RedisLoginAttemptRepository,
    },
    {
      provide: REFRESH_TOKEN_GENERATOR,
      useExisting: RandomRefreshTokenGenerator,
    },
    LockoutPolicy,

    LoginUseCase,
    RefreshSessionUseCase,
    LogoutUseCase,
    ListSessionsUseCase,
    RevokeSessionUseCase,

    PasswordChangedSessionRevoker,
  ],
  exports: [
    LoginUseCase,
    RefreshSessionUseCase,
    LogoutUseCase,
    ListSessionsUseCase,
    RevokeSessionUseCase,
    SESSION_REPOSITORY,
    LOGIN_ATTEMPT_REPOSITORY,
  ],
})
export class AuthenticationModule {}
