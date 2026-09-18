import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Email } from '../../../shared/domain/value-objects/email';
import { Password } from '../../../shared/domain/value-objects/password';
import {
  PASSWORD_HASHER,
  PasswordHash,
  PasswordHasher,
} from '../../../shared/domain/value-objects/password-hash';
import { Credential } from '../../domain/aggregates/credential';
import { Membership } from '../../domain/aggregates/membership';
import { Organization } from '../../domain/aggregates/organization';
import { User } from '../../domain/aggregates/user';
import { OrgId } from '../../domain/value-objects/org-id';
import { OrgSlug } from '../../domain/value-objects/org-slug';
import { Role } from '../../domain/value-objects/role';
import { UserId } from '../../domain/value-objects/user-id';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../domain/ports/credential.repository.port';
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

export interface RegisterUserInput {
  email: string;
  password: string;
  /**
   * Optional. If provided, the user joins the org with this slug.
   * If omitted, the auth service derives the org from the email domain
   * (via `OrganizationDomain`), or creates a personal org if no domain
   * is registered.
   */
  organizationSlug?: string;
  displayName?: string | null;
}

export interface RegisterUserResult {
  userId: string;
  organizationId: string;
  organizationSlug: string;
  email: string;
  /** True if a brand-new personal org was auto-created for this user. */
  autoCreatedOrg: boolean;
}

/**
 * Register a new user.
 *
 * Org-resolution rules (in priority order):
 *
 *   1. If `organizationSlug` is provided → look up the org by slug.
 *      Throws if not found.
 *   2. Else, extract the email domain and look up `OrganizationDomain`.
 *      If found, join that org. If not found:
 *      3. Auto-create a personal org with `slug = personal-<short-uuid>`,
 *         `name = <email-local-part>'s Workspace`.
 *
 * The first user to register for a given org gets the `OWNER` role.
 * Subsequent users get `MEMBER`. For V1 (single-org-per-user), only the
 * first-user-is-owner rule applies in practice.
 *
 * Atomicity: the entire flow (org create + user create + membership +
 * credential) runs inside one Prisma transaction.
 *
 * Event publishing: we drain the User's `UserRegistered` event AFTER the
 * transaction commits. This is the documented sharp edge of the
 * in-memory bus — if the process crashes between commit and publish,
 * downstream subscribers won't fire for this user. Acceptable for V1;
 * the proper fix is an outbox table (added when we move off the in-memory
 * bus).
 */
@Injectable()
export class RegisterUserUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(PASSWORD_HASHER) private readonly passwordHasher: PasswordHasher,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(CREDENTIAL_REPOSITORY)
    private readonly credentialRepo: CredentialRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(ORGANIZATION_DOMAIN_REPOSITORY)
    private readonly organizationDomainRepo: OrganizationDomainRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
  ) {}

  public async execute(input: RegisterUserInput): Promise<RegisterUserResult> {
    // Validate inputs at the use-case boundary.
    const email = Email.create(input.email);
    const password = Password.create(input.password);
    const explicitSlug = input.organizationSlug
      ? OrgSlug.create(input.organizationSlug)
      : null;
    const displayName = input.displayName?.trim() || null;

    // Hash the password outside the transaction (argon2 is ~50ms CPU).
    const hashString = await this.passwordHasher.hash(
      password.toHashableString(),
    );
    const passwordHash = PasswordHash.fromHashString(hashString);
    password.dispose();

    const { user, organization, autoCreatedOrg } = await this.txRunner.run<{
      user: User;
      organization: Organization;
      autoCreatedOrg: boolean;
    }>(async (tx: Tx) => {
      // Email-collision check first — applies regardless of org path.
      if (await this.userRepo.existsWithEmail(tx, email.value)) {
        throw new DomainError(
          'identity.email.taken',
          'A user with this email already exists',
          { email: email.value },
        );
      }

      // Resolve the organization.
      const resolved = await this.resolveOrganization(tx, email, explicitSlug);
      const { organization, autoCreatedOrg } = resolved;

      // Create User.
      const user = User.register({
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
        userId: UserId.create(this.idGenerator.generate()),
        organizationId: organization.id,
        email,
        displayName,
      });
      await this.userRepo.save(tx, user);

      // Create Membership. First user of an org is OWNER; subsequent
      // users (or users joining an existing org) are MEMBER.
      const isFirstUser = await this.isFirstUserInOrg(tx, organization.id);
      const role = isFirstUser ? Role.create('OWNER') : Role.create('MEMBER');

      const membership = Membership.create({
        id: this.idGenerator.generate(),
        userId: user.id,
        organizationId: organization.id,
        role,
        clock: this.clock,
      });
      await this.membershipRepo.save(tx, membership);

      // Create Credential.
      const credential = Credential.create({
        clock: this.clock,
        userId: user.id,
        passwordHash,
      });
      await this.credentialRepo.save(tx, credential);

      return { user, organization, autoCreatedOrg };
    });

    await this.eventBus.publishAll(user.pullDomainEvents());

    return {
      userId: user.id.value,
      organizationId: organization.id.value,
      organizationSlug: organization.slug.value,
      email: user.email.value,
      autoCreatedOrg,
    };
  }

  /**
   * Resolve which organization the new user should join.
   *
   * Returns the existing org (looked up by slug or domain) or a freshly
   * created personal org. The `autoCreatedOrg` flag in the return value
   * tells the caller which path was taken.
   */
  private async resolveOrganization(
    tx: Tx,
    email: Email,
    explicitSlug: OrgSlug | null,
  ): Promise<{ organization: Organization; autoCreatedOrg: boolean }> {
    // Path 1: explicit slug provided.
    if (explicitSlug) {
      const org = await this.organizationRepo.findBySlug(tx, explicitSlug);
      if (!org) {
        throw new DomainError(
          'domain.invariant_violation',
          'No organization with that slug exists',
          { slug: explicitSlug.value },
        );
      }
      return { organization: org, autoCreatedOrg: false };
    }

    // Path 2: extract email domain and look up.
    const domain = email.value.split('@')[1]?.toLowerCase();
    if (domain) {
      const match = await this.organizationDomainRepo.findByDomain(tx, domain);
      if (match) {
        const org = await this.organizationRepo.findById(
          tx,
          OrgId.create(match.organizationId),
        );
        if (org) {
          return { organization: org, autoCreatedOrg: false };
        }
        // Domain row points to a non-existent org — fall through to the
        // personal-org path. Should never happen in practice (the FK
        // cascade deletes domain rows when their org is deleted).
      }
    }

    // Path 3: auto-create a personal org.
    const personalOrg = await this.createPersonalOrg(tx, email.value);
    return { organization: personalOrg, autoCreatedOrg: true };
  }

  /**
   * Create a brand-new "personal" organization for the user. Slug is
   * `personal-<short-uuid>` to avoid collisions; name is derived from
   * the email local-part for human readability.
   */
  private async createPersonalOrg(
    tx: Tx,
    rawEmail: string,
  ): Promise<Organization> {
    const localPart = rawEmail.split('@')[0] ?? 'user';
    const slug = `personal-${this.idGenerator.generate().slice(0, 12)}`;
    const name = `${localPart}'s workspace`;

    const org = Organization.create({
      clock: this.clock,
      id: OrgId.create(this.idGenerator.generate()),
      slug: OrgSlug.create(slug),
      name: name.slice(0, 120), // respect the 120-char cap
    });
    await this.organizationRepo.save(tx, org);
    return org;
  }

  /**
   * True if no user currently belongs to this org. Used to decide
   * OWNER vs MEMBER role at registration time.
   */
  private async isFirstUserInOrg(tx: Tx, orgId: OrgId): Promise<boolean> {
    const existing = await this.membershipRepo.findByOrganizationId(tx, orgId);
    return existing.length === 0;
  }
}
