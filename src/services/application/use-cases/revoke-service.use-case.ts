import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import { ServiceEntitlement } from '../../domain/aggregates/service-entitlement';
import {
  SERVICE_ENTITLEMENT_REPOSITORY,
  ServiceEntitlementRepository,
} from '../../domain/ports/service-entitlement.repository.port';
import {
  SERVICE_REPOSITORY,
  ServiceRepository,
} from '../../domain/ports/service.repository.port';
import { ServiceSlug } from '../../domain/value-objects/service-slug';

export interface RevokeServiceInput {
  serviceSlug: string;
  organizationSlug: string;
  /** Admin key performing the action — recorded in the audit payload. */
  adminKeyId?: string | null;
}

export interface RevokeServiceResult {
  entitlement: ServiceEntitlement;
  /** True when this call actually flipped the status (idempotent otherwise). */
  revoked: boolean;
}

/**
 * Revoke an organization's entitlement to a catalog service.
 *
 * Terminal at the entitlement level: the row stays (audit trail) with
 * status REVOKED, and token issuance stops minting the service scope.
 * Re-granting later reactivates the same row.
 *
 * Idempotent: revoking an already-REVOKED row returns it unchanged with
 * `revoked: false`.
 *
 * Throws:
 *   - `services.service.not_found` — unknown service slug.
 *   - `identity.organization.not_found` — unknown org slug.
 *   - `services.entitlement.not_found` — no grant row to revoke.
 */
@Injectable()
export class RevokeServiceUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(SERVICE_REPOSITORY)
    private readonly serviceRepo: ServiceRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(SERVICE_ENTITLEMENT_REPOSITORY)
    private readonly entitlementRepo: ServiceEntitlementRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: RevokeServiceInput,
  ): Promise<RevokeServiceResult> {
    const serviceSlug = ServiceSlug.create(input.serviceSlug);
    const orgSlug = OrgSlug.create(input.organizationSlug);

    const { entitlement, revoked } = await this.txRunner.run<{
      entitlement: ServiceEntitlement;
      revoked: boolean;
    }>(async (tx: Tx) => {
      const service = await this.serviceRepo.findBySlug(tx, serviceSlug);
      if (!service) {
        throw new DomainError(
          'services.service.not_found',
          'No catalog service with this slug',
          { serviceSlug: serviceSlug.value },
        );
      }
      const org = await this.organizationRepo.findBySlug(tx, orgSlug);
      if (!org) {
        throw new DomainError(
          'identity.organization.not_found',
          'No organization with this slug',
          { organizationSlug: orgSlug.value },
        );
      }

      const existing = await this.entitlementRepo.findByOrgAndService(
        tx,
        org.id,
        service.id,
      );
      if (!existing) {
        throw new DomainError(
          'services.entitlement.not_found',
          'This organization has no grant for the service',
          {
            serviceSlug: serviceSlug.value,
            organizationSlug: orgSlug.value,
          },
        );
      }
      if (!existing.isActive() && existing.status === 'REVOKED') {
        return { entitlement: existing, revoked: false };
      }
      const revokedRow = await this.entitlementRepo.save(
        tx,
        existing.revoke(this.clock),
      );
      return { entitlement: revokedRow, revoked: true };
    });

    if (revoked) {
      await this.recordAuditEventUc.execute({
        userId: null,
        eventType: 'services.entitlement.revoked',
        payload: {
          serviceSlug: serviceSlug.value,
          organizationSlug: orgSlug.value,
          adminKeyId: input.adminKeyId ?? null,
        },
      });
    }

    return { entitlement, revoked };
  }
}
