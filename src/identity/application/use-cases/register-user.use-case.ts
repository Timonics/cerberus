import { Inject, Injectable } from '@nestjs/common';
import { randomUUID, createHash } from 'node:crypto';
import { Prisma } from '@prisma/client';
import {
  CLOCK,
  Clock,
  DomainError,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  OUTBOX,
  Outbox,
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
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
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
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';

export interface RegisterUserInput {
  email: string;
  password: string;
  /** Optional — caller IP address for audit-log + rate-limit. */
  ipAddress?: string | null;
  /** Optional — caller user-agent string for audit-log. */
  userAgent?: string | null;
  /**
   * Optional. If provided, the user joins the org with this slug.
   * If omitted, the auth service derives the org from the registered
   * app's `defaultOrgSlug` and finally creates a personal org.
   *
   * 2026-10-19 audit MEDIUM (email-domain auto-join): the email-domain
   * lookup (`OrganizationDomain`) used to happen HERE, granting org
   * membership before email ownership was proven (`attacker@acme.com`
   * got org-scoped tokens with no verification). The domain match now
   * happens only AFTER `identity.email.verified`, in
   * `EmailVerifiedDomainJoinHandler`.
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
 * 2026-10-19 audit LOW (registration email oracle): when the email is
 * already taken — or a concurrent registration wins the unique race —
 * the use-case returns this OPAQUE stub with the SAME shape as a real
 * registration result (HTTP 201 either way). Callers can no longer
 * distinguish "account exists" from "account created".
 */
function opaqueDuplicateResult(email: Email): RegisterUserResult {
  return {
    userId: randomUUID(),
    organizationId: randomUUID(),
    organizationSlug: 'personal',
    email: email.value,
    autoCreatedOrg: true,
  };
}

/** True when the Prisma error is a unique-constraint violation. */
function isUniqueViolation(err: unknown): boolean {
  return (
    err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002'
  );
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
 *   3. Else, auto-create a personal org with `slug = personal-<short-uuid>`,
 *      `name = <email-local-part>'s Workspace`.
 *
 * (The email-domain `OrganizationDomain` match no longer happens at
 * registration — it runs after email verification. See
 * `EmailVerifiedDomainJoinHandler`.)
 *
 * Duplicate email (existing row OR P2002 unique race): nothing is
 * created, `identity.registration.duplicate` is audited, and an opaque
 * stub with the same result shape is returned so account existence is
 * not leaked (2026-10-19 audit LOW).
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
    @Inject(OUTBOX) private readonly outbox: Outbox,
    @Inject(PASSWORD_HASHER) private readonly passwordHasher: PasswordHasher,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(CREDENTIAL_REPOSITORY)
    private readonly credentialRepo: CredentialRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
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

    const outcome = await this.txRunner
      .run<{
        user: User;
        organization: Organization;
        autoCreatedOrg: boolean;
      } | null>(async (tx: Tx) => {
        // Email-collision check first — applies regardless of org path.
        // 2026-10-19 audit LOW: on collision we return an opaque stub
        // (201, same shape) instead of throwing identity.email.taken,
        // which leaked account existence.
        if (await this.userRepo.existsWithEmail(tx, email.value)) {
          return null;
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

        // V1.5 outbox: drain the user's domain events and persist them
        // to the outbox in the same transaction. The OutboxRelay will
        // re-publish them through the in-process bus after commit.
        // Crashing between commit and relay now leaves the events
        // durably stored rather than lost.
        await this.outbox.appendAll(tx, user.pullDomainEvents());

        return { user, organization, autoCreatedOrg };
      })
      .catch((err: unknown) => {
        // 2026-10-19 audit LOW: a concurrent registration can win the
        // email-unique race and surface as P2002 mid-transaction. Treat
        // it exactly like a visible duplicate — opaque stub, no 500.
        if (isUniqueViolation(err)) {
          return null;
        }
        throw err;
      });

    if (outcome === null) {
      // Duplicate email (existing row or unique race): nothing was
      // created. Audit + return the opaque stub. The email is stored
      // only as a sha-256 — audit payloads are retained 90 days and
      // shouldn't carry plaintext addresses (registration rows don't
      // exist for these attempts, so there's no other record).
      await this.recordAuditEventUc.execute({
        userId: null,
        eventType: 'identity.registration.duplicate',
        payload: {
          emailSha256: createHash('sha256')
            .update(email.value, 'utf8')
            .digest('hex'),
        },
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
      });
      return opaqueDuplicateResult(email);
    }
    const { user, organization, autoCreatedOrg } = outcome;

    // (Events were already persisted to the outbox inside the tx; no
    // post-commit publish needed.)

    // Audit-log: identity.user.registered.
    // V1.5 fix: the audit_log table was empty in V1 because no BC was
    // writing to it. Wire the key identity events so the table becomes
    // useful for support investigations + admin audit search.
    await this.recordAuditEventUc.execute({
      userId: user.id.value,
      eventType: 'identity.user.registered',
      payload: {
        email: user.email.value,
        organizationId: organization.id.value,
        organizationSlug: organization.slug.value,
        autoCreatedOrg,
      },
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
    });

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
   *   3. Auto-create a personal org.
   *
   * The email-domain `OrganizationDomain` match intentionally does NOT
   * run here — new users are unverified at registration, and joining
   * an org on the strength of an unverified email domain granted
   * org-scoped tokens to whoever typed `victim@acme.com` (2026-10-19
   * audit MEDIUM). The match runs post-verification in
   * `EmailVerifiedDomainJoinHandler`.
   *
   * Returns the existing org (looked up by slug) or a freshly created
   * personal org. The `autoCreatedOrg` flag in the return value tells
   * the caller which path was taken.
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
      // App references a missing org — fall through to the personal
      // org path. Should not happen in practice (the apps table is
      // admin-managed), but we degrade gracefully.
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
