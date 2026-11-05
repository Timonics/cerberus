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

export interface GrantServiceInput {
  serviceSlug: string;
  organizationSlug: string;
  /** Admin key performing the action — recorded in the audit payload. */
  adminKeyId?: string | null;
}

export interface GrantServiceResult {
  entitlement: ServiceEntitlement;
  /** True when an existing SUSPENDED/REVOKED row was reactivated. */
  reactivated: boolean;
}

/**
 * Grant an organization access to a catalog service.
 *
 * One row per (org, service): when a row already exists it is
 * reactivated (SUSPENDED/REVOKED → ACTIVE); an already-ACTIVE grant is
 * a conflict. The grant commits atomically; audit follows outside the
 * tx like the other admin flows.
 *
 * Throws:
 *   - `services.service.not_found` — unknown service slug.
 *   - `identity.organization.not_found` — unknown org slug.
 *   - `services.entitlement.already_active` — grant already exists.
 */
@Injectable()
export class GrantServiceUseCase {
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

  public async execute(input: GrantServiceInput): Promise<GrantServiceResult> {
    const serviceSlug = ServiceSlug.create(input.serviceSlug);
    const orgSlug = OrgSlug.create(input.organizationSlug);

    const { entitlement, reactivated } = await this.txRunner.run<{
      entitlement: ServiceEntitlement;
      reactivated: boolean;
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
      if (existing) {
        if (existing.isActive()) {
          throw new DomainError(
            'services.entitlement.already_active',
            'This organization already has an active grant for the service',
            {
              serviceSlug: serviceSlug.value,
              organizationSlug: orgSlug.value,
            },
          );
        }
        const reactivatedRow = await this.entitlementRepo.save(
          tx,
          existing.reactivate(this.clock),
        );
        return { entitlement: reactivatedRow, reactivated: true };
      }

      const granted = ServiceEntitlement.grant({
        clock: this.clock,
        id: this.idGenerator.generate(),
        organizationId: org.id,
        serviceId: service.id,
      });
      const saved = await this.entitlementRepo.save(tx, granted);
      return { entitlement: saved, reactivated: false };
    });

    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'services.entitlement.granted',
      payload: {
        serviceSlug: serviceSlug.value,
        organizationSlug: orgSlug.value,
        reactivated,
        adminKeyId: input.adminKeyId ?? null,
      },
    });

    return { entitlement, reactivated };
  }
}
