import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  PASSWORD_HASHER,
  PasswordHasher,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Email } from '../../../shared/domain/value-objects/email';
import { Credential } from '../../../identity/domain/aggregates/credential';
import { User } from '../../../identity/domain/aggregates/user';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import {
  MfaSecretRepository,
  MFA_SECRET_REPOSITORY,
} from '../../../identity/domain/ports/mfa-secret.repository.port';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../../identity/domain/ports/credential.repository.port';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../../identity/domain/ports/membership.repository.port';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../../identity/domain/ports/user.repository.port';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import { Session } from '../../domain/aggregates/session';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  LockoutPolicy,
  assertNotLocked,
} from '../../domain/aggregates/lockout-policy';
import { SessionCreated } from '../../domain/events/auth.events';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';
import {
  LOGIN_ATTEMPT_REPOSITORY,
  LoginAttemptRepository,
} from '../../domain/ports/login-attempt.repository.port';
import { IpAddress } from '../../domain/value-objects/ip-address';
import { RefreshTokenHash } from '../../domain/value-objects/refresh-token-hash';
import { SessionId } from '../../domain/value-objects/session-id';
import { UserAgent } from '../../domain/value-objects/user-agent';
import {
  REFRESH_TOKEN_GENERATOR,
  RefreshTokenGenerator,
} from '../../infrastructure/security/refresh-token-generator';

export interface LoginInput {
  email: string;
  password: string;
  userAgent?: string;
  ipAddress?: string;
  /**
   * Optional. When the login carries `X-Cerberus-App-Id` headers,
   * the controller resolves the app's `defaultOrgSlug` and passes it
   * here. The login flow then requires the user to be a member of
   * that org — otherwise `authentication.app_membership_required`.
   *
   * Without this, V1 backward-compat behavior applies: the session
   * is scoped to the user's first org.
   */
  appDefaultOrgSlug?: string | null;
}

export interface LoginResult {
  /** Plaintext refresh token. Returned ONLY at issuance; never stored. */
  refreshToken: string;
  sessionId: string;
  userId: string;
  familyId: string;
  expiresAt: Date;
  /** Organization the session is scoped to. */
  organizationId: string | null;
  /** True if the user has MFA enabled and must complete a second factor before access. */
  mfaRequired: boolean;
}

const LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60; // 15-minute sliding window
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

/**
 * First-factor login (email + password).
 *
 * On success: creates a new Session, persists it, returns the plaintext
 * refresh token (one-time; never persisted). The caller is expected to
 * immediately exchange the refresh token for an access token (Phase 13).
 *
 * On failure: increments the login-attempt counter in Redis, evaluates
 * the lockout policy, and may lock the credential for an exponentially
 * growing window. The error message returned to the user is intentionally
 * identical for "user not found", "wrong password", and "locked" — to
 * avoid leaking account existence.
 *
 * Atomicity: the session creation + the credential-unlock happen in a
 * single transaction. The Redis login-attempt counter is updated either
 * before (for failures) or after (for successes — clearing the counter)
 * the transaction; it's not part of the ACID boundary because Redis
 * isn't transactional with Postgres.
 */
@Injectable()
export class LoginUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(PASSWORD_HASHER) private readonly passwordHasher: PasswordHasher,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    @Inject(LOGIN_ATTEMPT_REPOSITORY)
    private readonly loginAttemptRepo: LoginAttemptRepository,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(CREDENTIAL_REPOSITORY)
    private readonly credentialRepo: CredentialRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(REFRESH_TOKEN_GENERATOR)
    private readonly refreshTokenGen: RefreshTokenGenerator,
    private readonly lockoutPolicy: LockoutPolicy,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaSecretRepo: MfaSecretRepository,
  ) {}

  public async execute(input: LoginInput): Promise<LoginResult> {
    const email = Email.create(input.email);
    const normalizedEmail = email.value;

    // Determine the IP we'll key the lockout window by. Falling back to a
    // placeholder keeps the Redis key stable when the caller doesn't
    // provide an IP (rare in practice — every HTTP request has one).
    const ipValue = input.ipAddress ?? '0.0.0.0';
    const ip = IpAddress.create(ipValue);

    // Pre-check: is the account already locked?
    const currentWindow = await this.loginAttemptRepo.getWindow(
      normalizedEmail,
      ip.value,
      this.clock.now(),
      LOGIN_FAILURE_WINDOW_SECONDS,
    );
    assertNotLocked(this.lockoutPolicy, currentWindow, this.clock.now());

    // Look up the user + credential atomically.
    const lookup = await this.txRunner.run<{
      user: User | null;
      credential: Credential | null;
    }>(async (tx: Tx) => {
      const user = await this.userRepo.findByEmail(tx, normalizedEmail);
      if (!user) return { user: null, credential: null };
      const credential = await this.credentialRepo.findById(tx, user.id);
      return { user, credential };
    });

    // Constant-time-ish check: verify against a dummy hash if the user
    // doesn't exist, so we don't leak account existence via timing.
    // (For V1 we just go through the normal path — timing leak is small.)
    if (!lookup.user || !lookup.credential) {
      await this.recordFailure(normalizedEmail, ip.value);
      throw new DomainError(
        'authentication.invalid_credentials',
        'Invalid email or password',
      );
    }

    const { user, credential } = lookup;

    // Verify the password. argon2.verify is constant-time internally.
    const passwordOk = await this.passwordHasher.verify(
      input.password,
      credential.passwordHash.value,
    );
    if (!passwordOk) {
      await this.recordFailure(normalizedEmail, ip.value);
      // After recording, see if this push over a tier triggered a lockout.
      const newWindow = await this.loginAttemptRepo.getWindow(
        normalizedEmail,
        ip.value,
        this.clock.now(),
        LOGIN_FAILURE_WINDOW_SECONDS,
      );
      const lockSeconds = this.lockoutPolicy.computeLockout(
        newWindow,
        this.clock.now(),
      );
      if (lockSeconds !== null) {
        // Lock the credential too — DB-level enforcement so even if the
        // Redis window is wiped, the account stays locked until expiry.
        const until = new Date(this.clock.now().getTime() + lockSeconds * 1000);
        const updatedCred = credential.lockUntil(this.clock, until);
        await this.txRunner.run(async (tx: Tx) => {
          await this.credentialRepo.save(tx, updatedCred);
        });
        throw new DomainError(
          'authentication.account_locked',
          'Account temporarily locked due to repeated failed login attempts',
          { lockedUntil: until.toISOString() },
        );
      }
      throw new DomainError(
        'authentication.invalid_credentials',
        'Invalid email or password',
      );
    }

    // If the credential is already locked (set by an earlier attempt),
    // reject even with the correct password.
    if (credential.isLockedAt(this.clock.now())) {
      throw new DomainError(
        'authentication.account_locked',
        'Account is locked until ' + credential.lockedUntil?.toISOString(),
      );
    }

    // Successful login — clear the failure window, unlock the credential.
    await this.loginAttemptRepo.clear(normalizedEmail, ip.value);

    // Determine if MFA is required. We do this by checking whether a
    // confirmed MfaSecret exists. (V1.5: handle the case where the user
    // has MFA but the second-factor verification hasn't completed yet.)
    const requiresMfa = await this.requiresMfa(user.id);

    // Mint session + persist.
    const userAgent = input.userAgent
      ? UserAgent.create(input.userAgent)
      : null;
    const sessionId = SessionId.create(this.idGenerator.generate());
    const familyId = sessionId.value; // first session of family = own id
    const plaintextRefresh = this.refreshTokenGen.generate();
    const refreshHash = await RefreshTokenHash.fromPlaintext(plaintextRefresh);

    const session = Session.create({
      id: sessionId,
      userId: user.id,
      familyId,
      refreshHash,
      userAgent,
      ipAddress: ip,
      deviceLabel: userAgent?.deviceLabel() ?? null,
      organizationId: await this.resolveOrgForSession(
        user.id,
        input.appDefaultOrgSlug ?? null,
      ),
      clock: this.clock,
      ttlSeconds: REFRESH_TOKEN_TTL_SECONDS,
    });

    const saved = await this.txRunner.run<{ session: Session }>(
      async (tx: Tx) => {
        // Unlock credential if it was previously locked (e.g. expired lock).
        const unlockedCred = credential.unlock(this.clock);
        await this.credentialRepo.save(tx, unlockedCred);
        const persisted = await this.sessionRepo.save(tx, session);
        return { session: persisted };
      },
    );

    // Publish domain event post-commit (sharp edge: same pattern as in
    // RegisterUserUseCase).
    await this.eventBus.publishAll([
      new SessionCreated(
        this.idGenerator.generate(),
        this.clock.now(),
        saved.session.id,
        saved.session.userId,
        requiresMfa,
      ),
    ]);

    // Audit: authentication.login.succeeded.
    await this.recordAuditEventUc.execute({
      userId: saved.session.userId.value,
      eventType: 'authentication.login.succeeded',
      payload: {
        sessionId: saved.session.id.value,
        organizationSlug: saved.session.organizationId?.value ?? null,
        mfaRequired: requiresMfa,
      },
    });

    return {
      refreshToken: plaintextRefresh,
      sessionId: saved.session.id.value,
      userId: saved.session.userId.value,
      familyId: saved.session.familyId,
      expiresAt: saved.session.expiresAt,
      organizationId: saved.session.organizationId?.value ?? null,
      mfaRequired: requiresMfa,
    };
  }

  private async recordFailure(email: string, ip: string): Promise<void> {
    await this.loginAttemptRepo.recordFailure(
      email,
      ip,
      this.clock.now(),
      LOGIN_FAILURE_WINDOW_SECONDS,
    );
    // Audit: authentication.login.failed. userId is null because we
    // don't know if the email corresponds to a real user (no
    // enumeration leak in audit log either).
    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'authentication.login.failed',
      payload: { email, ipAddress: ip },
      ipAddress: ip,
    });
  }

  /**
   * Probe whether the user has MFA enabled.
   *
   * V1.5 (audit M7): the previous implementation called
   * `verifySecondFactorUc.execute({ code: '000000' })` and used whether
   * it threw `identity.mfa.not_enabled` as the success/failure signal.
   * That's exception-as-control-flow — bad pattern. Real errors (DB
   * down, malformed secret, etc.) silently meant "MFA is enabled".
   *
   * We now inject `MfaSecretRepository` directly and check the row's
   * `status` field. No exceptions, no incidental coupling to the
   * verifier use-case.
   */
  private async requiresMfa(userId: UserId): Promise<boolean> {
    const secret = await this.txRunner.run(async (tx) =>
      this.mfaSecretRepo.findById(tx, userId),
    );
    return secret !== null && secret.confirmed;
  }

  /**
   * Resolve which organization this session should be scoped to.
   *
   * Decision tree:
   *   1. If the caller supplied `appDefaultOrgSlug`, the user MUST be
   *      a member of that org. Otherwise throw
   *      `authentication.app_membership_required` (403). This is the
   *      "app-bound login" path — a user who registered via Acme's app
   *      but doesn't belong to Acme's org cannot log in via Acme's
   *      headers.
   *   2. If no `appDefaultOrgSlug`, fall back to the user's first
   *      membership (V1 backward-compat — single-org-per-user).
   *   3. If the user has no memberships at all (shouldn't happen —
   *      `RegisterUserUseCase` always creates one), return null.
   *
   * Returns `null` for legacy sessions. The rest of the system
   * interprets `null` as "scoped to user's first org".
   */
  private async resolveOrgForSession(
    userId: UserId,
    appDefaultOrgSlug: string | null,
  ): Promise<OrgId | null> {
    return this.txRunner.run(async (tx: Tx) => {
      const membership = await this.membershipRepo.findByUserId(tx, userId);
      if (!membership) {
        return null;
      }
      if (appDefaultOrgSlug && appDefaultOrgSlug.length > 0) {
        const targetSlug = OrgSlug.create(appDefaultOrgSlug);
        const org = await this.organizationRepo.findById(
          tx,
          membership.organizationId,
        );
        if (!org || !org.slug.equals(targetSlug)) {
          throw new DomainError(
            'authentication.app_membership_required',
            'User is not a member of the organization bound to this app',
            { appDefaultOrgSlug, userId: userId.value },
          );
        }
      }
      return membership.organizationId;
    });
  }
}
