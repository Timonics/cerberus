import { Inject, Injectable } from '@nestjs/common';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import {
  EntitlementWithService,
  SERVICE_ENTITLEMENT_REPOSITORY,
  ServiceEntitlementRepository,
} from '../../domain/ports/service-entitlement.repository.port';

export interface GetOrgServicesInput {
  organizationSlug: string;
}

/**
 * List an organization's entitlements (any status) with the service
 * rows joined — the admin "what does this org have" view.
 */
@Injectable()
export class GetOrgServicesUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(SERVICE_ENTITLEMENT_REPOSITORY)
    private readonly entitlementRepo: ServiceEntitlementRepository,
  ) {}

  public async execute(
    input: GetOrgServicesInput,
  ): Promise<{ entitlements: ReadonlyArray<EntitlementWithService> }> {
    const orgSlug = OrgSlug.create(input.organizationSlug);
    return this.txRunner.run<{
      entitlements: ReadonlyArray<EntitlementWithService>;
    }>(async (tx: Tx) => {
      const org = await this.organizationRepo.findBySlug(tx, orgSlug);
      if (!org) {
        throw new DomainError(
          'identity.organization.not_found',
          'No organization with this slug',
          { organizationSlug: orgSlug.value },
        );
      }
      const entitlements = await this.entitlementRepo.findWithServiceByOrgId(
        tx,
        org.id,
      );
      return { entitlements };
    });
  }
}
