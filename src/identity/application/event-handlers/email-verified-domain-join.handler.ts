import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { EmailAddressVerified } from '../../../engagement/domain/events/engagement.events';
import { Membership } from '../../domain/aggregates/membership';
import { Role } from '../../domain/value-objects/role';
import { UserId } from '../../domain/value-objects/user-id';
import { OrgId } from '../../domain/value-objects/org-id';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';
import {
  ORGANIZATION_DOMAIN_REPOSITORY,
  OrganizationDomainRepository,
} from '../../domain/ports/organization-domain.repository.port';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../domain/ports/organization.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';

/**
 * Cross-context event handler (2026-10-19 audit MEDIUM): when a user's
 * email address becomes VERIFIED, match the email domain against
 * `OrganizationDomain` and add the user to the matching org.
 *
 * This replaces the old registration-time auto-join, which granted
 * org membership — and org-scoped JWTs — on the strength of an
 * unverified email address. Membership now requires proof of ownership.
 *
 * Idempotency: if the user already holds a membership in the matched
 * org (e.g. the verification event is re-delivered), the join is
 * skipped silently. The user always also keeps their personal-org
 * membership (V1 code paths resolve orgs via the FIRST membership —
 * see `PrismaMembershipRepository.findByUserId`, which orders by
 * createdAt so the original membership stays first).
 */
@Injectable()
export class EmailVerifiedDomainJoinHandler implements OnModuleInit {
  private readonly logger = new Logger(EmailVerifiedDomainJoinHandler.name);

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(ORGANIZATION_DOMAIN_REPOSITORY)
    private readonly organizationDomainRepo: OrganizationDomainRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe('identity.email.verified', async (event) => {
      if (event instanceof EmailAddressVerified) {
        await this.handle(event);
      }
    });
  }

  public async handle(event: EmailAddressVerified): Promise<void> {
    try {
      const joined = await this.txRunner.run<boolean>(async (tx: Tx) => {
        const user = await this.userRepo.findById(
          tx,
          UserId.rehydrate(event.userId),
        );
        if (!user) {
          this.logger.warn(
            `identity.email.verified for unknown user ${event.userId}, skipping domain join`,
          );
          return false;
        }

        const domain = event.email.split('@')[1]?.toLowerCase();
        if (!domain) return false;
        const match = await this.organizationDomainRepo.findByDomain(
          tx,
          domain,
        );
        if (!match) return false;

        const orgId = OrgId.create(match.organizationId);
        const org = await this.organizationRepo.findById(tx, orgId);
        if (!org) return false;

        // Already a member (redelivery / re-verification)? Skip.
        const members = await this.membershipRepo.findByOrganizationId(
          tx,
          orgId,
        );
        if (members.some((m) => m.userId.value === event.userId)) {
          return false;
        }

        const membership = Membership.create({
          id: this.idGenerator.generate(),
          clock: this.clock,
          userId: UserId.rehydrate(event.userId),
          organizationId: orgId,
          role: Role.create('MEMBER'),
        });
        await this.membershipRepo.save(tx, membership);
        return true;
      });

      if (joined) {
        await this.recordAuditEventUc.execute({
          userId: event.userId,
          eventType: 'identity.organization.joined_by_domain',
          payload: {
            emailDomain: event.email.split('@')[1]?.toLowerCase() ?? null,
          },
        });
        this.logger.log(
          `User ${event.userId} joined org via verified email domain`,
        );
      }
    } catch (err) {
      this.logger.error(
        `Failed domain-join for verified email of user ${event.userId}: ${String(err)}`,
      );
    }
  }
}
