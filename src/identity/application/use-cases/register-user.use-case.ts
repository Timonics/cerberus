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
import { PasswordHash } from '../../../shared/domain/value-objects/password-hash';
import { UserId } from '../../domain/value-objects/user-id';
import { OrgSlug } from '../../domain/value-objects/org-slug';
import { OrgId } from '../../domain/value-objects/org-id';
import { Role } from '../../domain/value-objects/role';
import { User } from '../../domain/aggregates/user';
import { Organization } from '../../domain/aggregates/organization';
import { Credential } from '../../domain/aggregates/credential';
import { Membership } from '../../domain/aggregates/membership';
import {
  PasswordHasher,
  PASSWORD_HASHER,
} from '../../../shared/domain/value-objects/password-hash';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../domain/ports/credential.repository.port';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../domain/ports/organization.repository.port';
import {
  ORGANIZATION_DOMAIN_REPOSITORY,
  OrganizationDomainRepository,
} from '../../domain/ports/organization-domain.repository.port';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';

export interface RegisterUserInput {
  email: string;
  password: string;
  /**
   * Optional. If provided, the user joins the org with this slug.
   * If omitted, the auth service derives the org from the registered
   * app's `defaultOrgSlug`, then from the email domain (via
   * `OrganizationDomain`), and finally creates a personal org.
   */
  organizationSlug?: string;
  /**
   * Optional. If present (validated upstream by the apps auth flow),
   * this app's `defaultOrgSlug` becomes the org-binding source —
   * unless an explicit `organizationSlug` is also provided, in which
   * case the explicit slug wins.
   *
   * V1: this is just an organizational hint; the actual auth happens
   * at the controller layer. The use-case doesn't re-verify the
   * app's API key — that's the guard's job.
   */
  appDefaultOrgSlug?: string | null;
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
 *   2. Else, if the registering app's `defaultOrgSlug` is present,
 *      look up the org by that slug. Falls through if the slug is
 *      missing the org row.
 *   3. Else, extract the email domain and look up `OrganizationDomain`.
 *      If found, join that org. If not found:
 *   4. Auto-create a personal org with `slug = personal-<short-uuid>`,
 *      `name = <email-local-part>'s Workspace`.
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
    const appDefaultOrgSlug =
      typeof input.appDefaultOrgSlug === 'string'
        ? input.appDefaultOrgSlug.trim() || null
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
      const resolved = await this.resolveOrganization(
        tx,
        email,
        explicitSlug,
        appDefaultOrgSlug,
      );
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

      // Create Credential.
      const credential = Credential.create({
        clock: this.clock,
        userId: user.id,
        passwordHash,
      });
      await this.credentialRepo.save(tx, credential);

      // Create Membership (OWNER if first, else MEMBER).
      const role = (await this.isFirstUserInOrg(tx, organization.id))
        ? Role.create('OWNER')
        : Role.create('MEMBER');
      const membership = Membership.create({
        id: this.idGenerator.generate(),
        clock: this.clock,
        userId: user.id,
        organizationId: organization.id,
        role,
      });
      await this.membershipRepo.save(tx, membership);

      return { user, organization, autoCreatedOrg };
    });

    // Publish post-commit events. Drains all pending domain events.
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
   * Path order (priority):
   *   1. Explicit `organizationSlug` from the caller.
   *   2. The registering app's `defaultOrgSlug` (if any).
   *   3. Email-domain lookup against `OrganizationDomain`.
   *   4. Auto-create a personal org.
   *
   * Returns the existing org (looked up by slug or domain) or a freshly
   * created personal org. The `autoCreatedOrg` flag in the return value
   * tells the caller which path was taken.
   */
  private async resolveOrganization(
    tx: Tx,
    email: Email,
    explicitSlug: OrgSlug | null,
    appDefaultOrgSlug: string | null,
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

    // Path 2: app-bound org slug. The guard upstream already verified
    // the app's API key — by this point we trust the slug, but the
    // org still has to actually exist.
    if (appDefaultOrgSlug && appDefaultOrgSlug.length > 0) {
      const appOrgSlug = OrgSlug.create(appDefaultOrgSlug);
      const org = await this.organizationRepo.findBySlug(tx, appOrgSlug);
      if (org) {
        return { organization: org, autoCreatedOrg: false };
      }
      // App references a missing org — fall through to domain match.
      // Should not happen in practice (the apps table is admin-managed),
      // but we degrade gracefully.
    }

    // Path 3: extract email domain and look up.
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

    // Path 4: auto-create a personal org.
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
