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
import { Membership } from '../../domain/aggregates/membership';
import { Organization } from '../../domain/aggregates/organization';
import { OrgId } from '../../domain/value-objects/org-id';
import { OrgSlug } from '../../domain/value-objects/org-slug';
import { Role } from '../../domain/value-objects/role';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../domain/ports/organization.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

export interface CreateOwnOrganizationInput {
  /** Unique slug (lowercase, hyphenated, not in the reserved blocklist). */
  slug: string;
  /** Display name (1-120 chars). */
  name: string;
  /** Optional description (≤ 500 chars). */
  description?: string | null;
  /** The authenticated user founding the org; becomes OWNER and moves into it. */
  callerUserId: string;
}

export interface CreateOwnOrganizationResult {
  organization: Organization;
}

/**
 * Self-service organization creation.
 *
 * Closes the onboarding gap where only operators could create orgs (via
 * the admin API). An authenticated user founds a new org: the org is
 * created, the caller gets an OWNER membership, and the caller's
 * `User.organizationId` moves to the new org in the SAME transaction
 * (V1 is single-org-per-user; the caller leaves their previous org,
 * typically the auto-created personal one).
 *
 * V1 sharp edges, accepted deliberately:
 *
 *   * Access tokens minted for the previous org stay valid until they
 *     expire (they are short-lived by design); the caller should
 *     re-login to get a token bound to the new org.
 *   * The abandoned previous org is left empty; the cleanup cron may
 *     reclaim it if it has no members.
 */
@Injectable()
export class CreateOwnOrganizationUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: CreateOwnOrganizationInput,
  ): Promise<CreateOwnOrganizationResult> {
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

    const callerUserId = UserId.create(input.callerUserId);

    const result = await this.txRunner.run<{
      organization: Organization;
      previousOrganizationId: string;
    }>(async (tx: Tx) => {
      const user = await this.userRepo.findById(tx, callerUserId);
      if (!user) {
        throw new DomainError(
          'identity.user.not_found',
          'User does not exist',
          { userId: callerUserId.value },
        );
      }
      const previousOrganizationId = user.organizationId.value;

      // Fail fast if the slug is already taken (the unique index also
      // enforces this at the DB level, but we want a friendly code).
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

      // Swap the caller's membership: drop the old one (V1 is
      // single-membership) and grant OWNER in the new org.
      const oldMembership = await this.membershipRepo.findByUserId(
        tx,
        callerUserId,
      );
      if (oldMembership) {
        await this.membershipRepo.delete(tx, oldMembership.id);
      }
      const membership = Membership.create({
        id: this.idGenerator.generate(),
        clock: this.clock,
        userId: callerUserId,
        organizationId: saved.id,
        role: Role.create('OWNER'),
      });
      await this.membershipRepo.save(tx, membership);

      // Move the user into the new org.
      await this.userRepo.save(
        tx,
        user.moveToOrganization(this.clock, saved.id),
      );

      return { organization: saved, previousOrganizationId };
    });

    await this.recordAuditEventUc.execute({
      userId: callerUserId.value,
      eventType: 'identity.organization.created_by_user',
      payload: {
        organizationId: result.organization.id.value,
        slug: input.slug,
        name: input.name,
        previousOrganizationId: result.previousOrganizationId,
      },
    });

    return { organization: result.organization };
  }
}
