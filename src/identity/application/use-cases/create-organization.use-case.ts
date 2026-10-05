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
import { Organization } from '../../domain/aggregates/organization';
import { OrgId } from '../../domain/value-objects/org-id';
import { OrgSlug } from '../../domain/value-objects/org-slug';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../domain/ports/organization.repository.port';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

export interface CreateOrganizationInput {
  /** Unique slug (lowercase, hyphenated, not in the reserved blocklist). */
  slug: string;
  /** Display name (1-120 chars). */
  name: string;
  /** Optional description (≤ 500 chars). */
  description?: string | null;
  /**
   * Who issued the request, for the `admin.organization.created`
   * audit row. API-key caller → null.
   */
  callerUserId?: string | null;
  /**
   * Which admin API key (if any) issued the request.
   */
  callerKeyId?: string | null;
}

export interface CreateOrganizationResult {
  organization: Organization;
}

/**
 * Operator endpoint to create an empty organization.
 *
 * V1: orgs are only created via user registration (the personal-org
 * fallback, or the email-domain auto-binding, or the explicit
 * `organizationSlug` flow). V1.5 adds this surface so administrators
 * can pre-create a tenant org, then have users register with
 * `?organizationSlug=<the-pre-created-slug>` and auto-join.
 *
 * The new org has no members — the first user to register with the
 * matching slug gets OWNER role.
 */
@Injectable()
export class CreateOrganizationUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: CreateOrganizationInput,
  ): Promise<CreateOrganizationResult> {
    const slug = OrgSlug.create(input.slug);
    const name = input.name.trim();
    if (name.length === 0) {
      throw new DomainError(
        'identity.organization.name_required',
        'Organization name is required',
      );
    }
    if (name.length > 120) {
      throw new DomainError(
        'identity.organization.name_too_long',
        'Organization name must be 120 characters or fewer',
        { length: name.length },
      );
    }
    if (input.description !== undefined && input.description !== null) {
      if (input.description.length > 500) {
        throw new DomainError(
          'identity.organization.description_too_long',
          'Description must be 500 characters or fewer',
          { length: input.description.length },
        );
      }
    }

    const result = await this.txRunner.run<{
      organization: Organization;
    }>(async (tx: Tx) => {
      // Fail fast if the slug is already taken. We do this check
      // INSIDE the tx so a concurrent create with the same slug
      // can't both succeed (the slug column has a unique index
      // so the DB also enforces it, but we want a friendly code).
      const existing = await this.organizationRepo.findBySlug(tx, slug);
      if (existing) {
        throw new DomainError(
          'identity.organization.slug_taken',
          'An organization with this slug already exists',
          { slug: input.slug },
        );
      }

      const organization = Organization.create({
        clock: this.clock,
        id: OrgId.create(this.idGenerator.generate()),
        slug,
        name,
      });
      const saved = await this.organizationRepo.save(tx, organization);
      return { organization: saved };
    });

    await this.recordAuditEventUc.execute({
      userId: input.callerUserId ?? null,
      eventType: 'admin.organization.created',
      payload: {
        organizationId: result.organization.id.value,
        slug: input.slug,
        name: input.name,
        callerKeyId: input.callerKeyId ?? null,
      },
    });

    return { organization: result.organization };
  }
}
