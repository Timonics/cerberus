import { Global, Module } from '@nestjs/common';
import { EngagementModule } from '../engagement/engagement.module';
import { IdentityModule } from '../identity/identity.module';
import { ProvisionServiceUseCase } from './application/use-cases/provision-service.use-case';
import { GrantServiceUseCase } from './application/use-cases/grant-service.use-case';
import { RevokeServiceUseCase } from './application/use-cases/revoke-service.use-case';
import { ListServicesUseCase } from './application/use-cases/list-services.use-case';
import { GetOrgServicesUseCase } from './application/use-cases/get-org-services.use-case';
import { SERVICE_REPOSITORY } from './domain/ports/service.repository.port';
import { SERVICE_ENTITLEMENT_REPOSITORY } from './domain/ports/service-entitlement.repository.port';
import { PrismaServiceRepository } from './infrastructure/persistence/prisma-service.repository';
import { PrismaServiceEntitlementRepository } from './infrastructure/persistence/prisma-service-entitlement.repository';

/**
 * Services bounded context — Nest wiring.
 *
 * The catalog of services this deployment offers plus per-organization
 * entitlements. Token issuance (Authorization) reads entitlements through
 * `SERVICE_ENTITLEMENT_REPOSITORY` to mint `service:<slug>` scopes; the
 * admin surface exposes provisioning/grant/revoke endpoints.
 *
 * Marked `@Global()` so both the public app (token issuance) and the
 * admin listener (provisioning endpoints) can inject the repositories
 * and use-cases without re-exporting symbols.
 */
@Global()
@Module({
  imports: [IdentityModule, EngagementModule],
  providers: [
    // Infrastructure
    PrismaServiceRepository,
    PrismaServiceEntitlementRepository,
    {
      provide: SERVICE_REPOSITORY,
      useClass: PrismaServiceRepository,
    },
    {
      provide: SERVICE_ENTITLEMENT_REPOSITORY,
      useClass: PrismaServiceEntitlementRepository,
    },

    // Use-cases
    ProvisionServiceUseCase,
    GrantServiceUseCase,
    RevokeServiceUseCase,
    ListServicesUseCase,
    GetOrgServicesUseCase,
  ],
  exports: [
    ProvisionServiceUseCase,
    GrantServiceUseCase,
    RevokeServiceUseCase,
    ListServicesUseCase,
    GetOrgServicesUseCase,
    SERVICE_REPOSITORY,
    SERVICE_ENTITLEMENT_REPOSITORY,
  ],
})
export class ServicesModule {}
