import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { Service } from '../../domain/aggregates/service';
import {
  SERVICE_REPOSITORY,
  ServiceRepository,
} from '../../domain/ports/service.repository.port';
import { ServiceSlug } from '../../domain/value-objects/service-slug';

export interface ProvisionServiceInput {
  slug: string;
  name: string;
  description?: string | null;
  /** Admin key performing the action — recorded in the audit payload. */
  adminKeyId?: string | null;
}

export interface ProvisionServiceResult {
  service: Service;
  /** True when the slug already existed and was updated/reactivated. */
  updated: boolean;
}

/**
 * Provision (register or update) a catalog service by slug.
 *
 * Upsert semantics keyed on the slug: a re-provision updates the display
 * name/description and reactivates an INACTIVE service. The slug itself
 * is immutable — it appears in issued JWTs.
 *
 * Audits `services.service.provisioned` with the admin key id; `userId`
 * is null because the actor is an admin operator, not an end user
 * (matches the admin-surface audit convention).
 */
@Injectable()
export class ProvisionServiceUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(SERVICE_REPOSITORY)
    private readonly serviceRepo: ServiceRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: ProvisionServiceInput,
  ): Promise<ProvisionServiceResult> {
    const slug = ServiceSlug.create(input.slug);
    const description = input.description ?? null;

    const { service, updated } = await this.txRunner.run<{
      service: Service;
      updated: boolean;
    }>(async (tx: Tx) => {
      const existing = await this.serviceRepo.findBySlug(tx, slug);
      if (existing) {
        let next = existing.rename(this.clock, input.name);
        next = next.setDescription(this.clock, description);
        if (!next.isActive()) {
          next = next.activate(this.clock);
        }
        const saved = await this.serviceRepo.save(tx, next);
        return { service: saved, updated: true };
      }
      const created = Service.create({
        clock: this.clock,
        id: this.idGenerator.generate(),
        slug,
        name: input.name,
        description,
      });
      const saved = await this.serviceRepo.save(tx, created);
      return { service: saved, updated: false };
    });

    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'services.service.provisioned',
      payload: {
        serviceSlug: slug.value,
        serviceName: service.name,
        updated,
        adminKeyId: input.adminKeyId ?? null,
      },
    });

    return { service, updated };
  }
}
