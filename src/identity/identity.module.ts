import { Global, Module } from '@nestjs/common';
import { AuthorizationModule } from '../authorization/authorization.module';
import { Argon2PasswordHasher } from './infrastructure/security/argon2-password-hasher';
import { PrismaCredentialRepository } from './infrastructure/persistence/prisma-credential.repository';
import { PrismaMembershipRepository } from './infrastructure/persistence/prisma-membership.repository';
import { PrismaMfaSecretRepository } from './infrastructure/persistence/prisma-mfa-secret.repository';
import { PrismaOrganizationDomainRepository } from './infrastructure/persistence/prisma-organization-domain.repository';
import { PrismaOrganizationRepository } from './infrastructure/persistence/prisma-organization.repository';
import { PrismaUserRepository } from './infrastructure/persistence/prisma-user.repository';
import { TotpService } from './infrastructure/security/totp.service';
import { ChangePasswordUseCase } from './application/use-cases/change-password.use-case';
import { ConfirmMfaEnrollmentUseCase } from './application/use-cases/confirm-mfa-enrollment.use-case';
import { DisableMfaUseCase } from './application/use-cases/disable-mfa.use-case';
import { EnableMfaUseCase } from './application/use-cases/enable-mfa.use-case';
import { GetUserUseCase } from './application/use-cases/get-user.use-case';
import { RegisterUserUseCase } from './application/use-cases/register-user.use-case';
import { CreateOrganizationUseCase } from './application/use-cases/create-organization.use-case';
import { UpdateDisplayNameUseCase } from './application/use-cases/update-display-name.use-case';
import { VerifySecondFactorUseCase } from './application/use-cases/verify-second-factor.use-case';
import { IdentityController } from './interfaces/http/identity.controller';
import { IdentityResolver } from './interfaces/graphql/identity.resolver';
import { PASSWORD_HASHER } from '../shared/domain/value-objects/password-hash';
import { CREDENTIAL_REPOSITORY } from './domain/ports/credential.repository.port';
import { MEMBERSHIP_REPOSITORY } from './domain/ports/membership.repository.port';
import { MFA_SECRET_REPOSITORY } from './domain/ports/mfa-secret.repository.port';
import { ORGANIZATION_DOMAIN_REPOSITORY } from './domain/ports/organization-domain.repository.port';
import { ORGANIZATION_REPOSITORY } from './domain/ports/organization.repository.port';
import { USER_REPOSITORY } from './domain/ports/user.repository.port';
import { AppsModule } from '../apps/apps.module';

/**
 * Identity bounded context — Nest wiring.
 *
 * Marked `@Global()` so the repository + hasher ports are visible to
 * other bounded contexts (Authentication needs them). The use-case
 * exports remain explicit.
 *
 * Imports `AppsModule` so the register controller can call
 * `VerifyAppApiKeyUseCase` for app-bound org resolution. Even though
 * `AppsModule` is itself `@Global()`, an explicit import here makes
 * the dependency visible to the IdentityController constructor scan
 * (some Nest versions don't auto-propagate `@Global()` providers to
 * controllers in modules that don't transitively import the global).
 */
@Global()
@Module({
  // AuthorizationModule is imported (despite also being @Global) so
  // that `JwtAuthGuard` — used by IdentityController via @UseGuards
  // — has its `JwtSignerService` dep resolved within IdentityModule's
  // DI tree. Without the explicit import, guards-injected deps that
  // are @Global() can fail to resolve when the controller's module
  // (IdentityModule) doesn't import the guard's owning module
  // (AuthorizationModule). V1.5 fix.
  imports: [AppsModule, AuthorizationModule],
  controllers: [IdentityController],
  providers: [
    // Infrastructure
    Argon2PasswordHasher,
    TotpService,
    {
      provide: CREDENTIAL_REPOSITORY,
      useClass: PrismaCredentialRepository,
    },
    {
      provide: MEMBERSHIP_REPOSITORY,
      useClass: PrismaMembershipRepository,
    },
    {
      provide: MFA_SECRET_REPOSITORY,
      useClass: PrismaMfaSecretRepository,
    },
    {
      provide: ORGANIZATION_REPOSITORY,
      useClass: PrismaOrganizationRepository,
    },
    {
      provide: ORGANIZATION_DOMAIN_REPOSITORY,
      useClass: PrismaOrganizationDomainRepository,
    },
    {
      provide: USER_REPOSITORY,
      useClass: PrismaUserRepository,
    },
    { provide: PASSWORD_HASHER, useExisting: Argon2PasswordHasher },

    // Use-cases
    RegisterUserUseCase,
    CreateOrganizationUseCase,
    ChangePasswordUseCase,
    EnableMfaUseCase,
    ConfirmMfaEnrollmentUseCase,
    DisableMfaUseCase,
    VerifySecondFactorUseCase,
    GetUserUseCase,
    UpdateDisplayNameUseCase,

    // GraphQL resolver
    IdentityResolver,
  ],
  exports: [
    RegisterUserUseCase,
    CreateOrganizationUseCase,
    ChangePasswordUseCase,
    EnableMfaUseCase,
    ConfirmMfaEnrollmentUseCase,
    DisableMfaUseCase,
    VerifySecondFactorUseCase,
    GetUserUseCase,
    UpdateDisplayNameUseCase,
    PASSWORD_HASHER,
    USER_REPOSITORY,
    CREDENTIAL_REPOSITORY,
    MEMBERSHIP_REPOSITORY,
    MFA_SECRET_REPOSITORY,
    ORGANIZATION_REPOSITORY,
    ORGANIZATION_DOMAIN_REPOSITORY,
  ],
})
export class IdentityModule {}
