import { Global, Module } from '@nestjs/common';
import { AuthenticationModule } from '../authentication/authentication.module';
import { JwtSignerService } from './infrastructure/crypto/jwt-signer.service';
import { JwtAuthGuard } from './interfaces/security/jwt-auth.guard';
import { ScopesGuard } from './interfaces/security/scopes.guard';
import { JoseRsaKeyPairGenerator } from './infrastructure/crypto/jose-rsa-key-pair-generator';
import { PrismaSigningKeyRepository } from './infrastructure/persistence/prisma-signing-key.repository';
import { GetJwksUseCase } from './application/use-cases/get-jwks.use-case';
import { IntrospectTokenUseCase } from './application/use-cases/introspect-token.use-case';
import { IssueAccessTokenUseCase } from './application/use-cases/issue-access-token.use-case';
import { RefreshTokenGrantUseCase } from './application/use-cases/refresh-token-grant.use-case';
import { RevokeTokenUseCase } from './application/use-cases/revoke-token.use-case';
import { RotateSigningKeyUseCase } from './application/use-cases/rotate-signing-key.use-case';
import { VerifyAccessTokenUseCase } from './application/use-cases/verify-access-token.use-case';
import { SIGNING_KEY_REPOSITORY } from './domain/ports/signing-key.repository.port';
import { RSA_KEY_PAIR_GENERATOR } from './infrastructure/crypto/jose-rsa-key-pair-generator';
import { JwksController } from './interfaces/http/oauth.controller';
import { OAuthAdminController } from './interfaces/http/oauth-admin.controller';
import { OAuthController } from './interfaces/http/oauth.controller';
import { AuthorizationResolver } from './interfaces/graphql/authorization.resolver';

/**
 * Authorization bounded context — Nest wiring.
 *
 * Marked `@Global()` so `JwtSignerService` is injectable from anywhere
 * (the Identity / Authentication bounded contexts may want to verify
 * JWTs in V2). Use-cases are explicit exports.
 */
@Global()
@Module({
  imports: [AuthenticationModule],
  controllers: [OAuthController, JwksController, OAuthAdminController],
  providers: [
    // Infrastructure
    PrismaSigningKeyRepository,
    JoseRsaKeyPairGenerator,
    JwtSignerService,
    {
      provide: SIGNING_KEY_REPOSITORY,
      useClass: PrismaSigningKeyRepository,
    },
    {
      provide: RSA_KEY_PAIR_GENERATOR,
      useExisting: JoseRsaKeyPairGenerator,
    },

    // Use-cases
    IssueAccessTokenUseCase,
    RefreshTokenGrantUseCase,
    IntrospectTokenUseCase,
    RevokeTokenUseCase,
    VerifyAccessTokenUseCase,
    GetJwksUseCase,
    RotateSigningKeyUseCase,

    // Guards (V1.5)
    JwtAuthGuard,
    ScopesGuard,

    // GraphQL resolver
    AuthorizationResolver,
  ],
  exports: [
    IssueAccessTokenUseCase,
    VerifyAccessTokenUseCase,
    GetJwksUseCase,
    JwtSignerService,
    RotateSigningKeyUseCase,
    SIGNING_KEY_REPOSITORY,
    JwtAuthGuard,
    ScopesGuard,
  ],
})
export class AuthorizationModule {}
