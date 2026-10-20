import { Inject, Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
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
  OUTBOX,
  Outbox,
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
import { TotpService } from '../../../identity/infrastructure/security/totp.service';
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
import { MintMfaPendingTokenUseCase } from './mint-mfa-pending-token.use-case';

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
  /**
   * 2026-10-19 audit fix C1: optional inline second factor. When the
   * user has MFA enabled and supplies a valid 6-digit TOTP code here,
   * the login completes in one round-trip: the session is created
   * MFA-verified and the normal token pair is returned. An invalid
   * code throws `identity.mfa.code_invalid` — the password has
   * already been verified at that point, so this leaks nothing about
   * the credential.
   */
  mfaCode?: string;
}

export interface LoginResult {
  /**
   * Plaintext refresh token. Returned ONLY at issuance; never stored.
   * Null when the login is MFA-pending — no refresh token exists
   * until the second factor completes (audit fix C1: a usable refresh
   * token in the mfaRequired response let a password-only attacker
   * bypass MFA via /v1/auth/refresh).
   */
  refreshToken: string | null;
  /**
   * 2026-10-19 audit fix C1: scoped JWT (scope `mfa:verify`) returned
   * ONLY when mfaRequired is true. Carries sub=userId + sid=sessionId
   * and is the credential the client presents to
   * POST /v1/identity/mfa/verify. Null otherwise.
   */
  mfaToken: string | null;
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
 * 2026-10-19 audit fix H-8: account-wide lockout. 10 failed attempts
 * against one email from ANY IPs within 15 minutes locks the account
 * for 15 minutes. The per-(email, ip) LockoutPolicy tiers still apply
 * on top (a single-IP attacker trips those at 5 failures first).
 */
const ACCOUNT_LOCK_THRESHOLD = 10;
const ACCOUNT_LOCK_WINDOW_SECONDS = 15 * 60;
const ACCOUNT_LOCK_SECONDS = 15 * 60;

/**
 * 2026-10-19 audit fix H-12: cap MFA-pending challenge issuances at
 * 10 per email per hour. Each issuance is positive confirmation that
 * the password is correct, so without a cap the mfaRequired response
 * is a password-validation oracle (and hands out session ids).
 */
const MFA_PENDING_ISSUANCE_LIMIT = 10;
const MFA_PENDING_WINDOW_SECONDS = 60 * 60;

/**
 * First-factor login (email + password), with optional inline second
 * factor.
 *
 * On success (no MFA, or inline mfaCode valid): creates a new Session,
 * persists it, returns the plaintext refresh token (one-time; never
 * persisted) and an access token is minted by the caller.
 *
 * On success with MFA pending: creates the Session with
 * mfaVerified=false, returns `{ mfaRequired: true, mfaToken,
 * sessionId }` — NO refresh token. The mfaToken is the scoped JWT
 * the client exchanges at POST /v1/identity/mfa/verify.
 *
 * On failure: increments the login-attempt counters in Redis, evaluates
 * the lockout policy, and may lock the credential for an exponentially
 * growing window. The error message returned to the user is
 * intentionally identical for "user not found", "wrong password", and
 * "locked" — to avoid leaking account existence.
 *
 * Atomicity: the session creation + the credential-unlock happen in a
 * single transaction. The Redis login-attempt counters are updated
 * either before (for failures) or after (for successes — clearing the
 * counters) the transaction; they're not part of the ACID boundary
 * because Redis isn't transactional with Postgres.
 */
@Injectable()
export class LoginUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(OUTBOX) private readonly outbox: Outbox,
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
    private readonly totp: TotpService,
    private readonly mintMfaPendingTokenUc: MintMfaPendingTokenUseCase,
  ) {}

  public async execute(input: LoginInput): Promise<LoginResult> {
    const email = Email.create(input.email);
    const normalizedEmail = email.value;

    // Determine the IP we'll key the lockout window by. Falling back to a
    // placeholder keeps the Redis key stable when the caller doesn't
    // provide an IP (rare in practice — every HTTP request has one).
    const ipValue = input.ipAddress ?? '0.0.0.0';
    const ip = IpAddress.create(ipValue);

    // Pre-check: is the account already locked? Two independent checks:
    //   1. per-(email, ip) sliding window → LockoutPolicy tiers
    //   2. per-email any-IP cumulative window (H-8) → fixed 15-min lock
    const currentWindow = await this.loginAttemptRepo.getWindow(
      normalizedEmail,
      ip.value,
      this.clock.now(),
      LOGIN_FAILURE_WINDOW_SECONDS,
    );
    assertNotLocked(this.lockoutPolicy, currentWindow, this.clock.now());

    const accountWindow = await this.loginAttemptRepo.getAccountWindow(
      normalizedEmail,
      this.clock.now(),
      ACCOUNT_LOCK_WINDOW_SECONDS,
    );
    this.assertAccountNotLocked(accountWindow);

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

    // Constant-time-ish check: verify against a dummy hash if the
    // user doesn't exist, so account-existence is not leaked via
    // timing. V1.5 (audit M-3): the previous code skipped argon2
    // entirely on the unknown-user path (~50ms shorter response),
    // which a timing-attack client could detect.
    //
    // We always perform exactly one argon2.verify call. The dummy
    // hash is a real argon2id-formatted string that will return
    // `false` for any plaintext — it exists so the verify path
    // takes the same ~50ms regardless of user existence. Argon2's
    // own `verify()` swallows the malformed-hash error in
    // Argon2PasswordHasher.verify() and returns `false`.
    const DUMMY_HASH =
      '$argon2id$v=19$m=65536,t=3,p=1$ZHVtbXlzYWx0Zm9yY29uc3RhbnR0aW1l' +
      'Y2hlY2tpbmcAAAAAAAAAAAA$ZPrQq5Z0qJD8m4lpqkS5eZ6xv7h8y9a0b1c2d3e4f5g';

    // Always do exactly one argon2 verify call. The dummy hash is
    // syntactically-valid argon2id; the actual verify returns `false`
    // for any plaintext because the salt doesn't match. The
    // Argon2PasswordHasher swallows any malformed-input exception
    // and returns `false`, so even a malformed dummy would work,
    // but a syntactically valid one is more robust.
    let passwordOk = false;
    if (lookup.user !== null && lookup.credential !== null) {
      passwordOk = await this.passwordHasher.verify(
        input.password,
        lookup.credential.passwordHash.value,
      );
    } else {
      // Equalize timing — exactly one argon2 call.
      await this.passwordHasher.verify(input.password, DUMMY_HASH);
    }

    if (!lookup.user || !lookup.credential) {
      await this.recordFailure(normalizedEmail, ip.value);
      throw new DomainError(
        'authentication.invalid_credentials',
        'Invalid email or password',
      );
    }

    const { user, credential } = lookup;

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
        // Audit: V1.5 fix — write BOTH the auth-layer event (records
        // the lockout action) and the identity-layer event (records
        // that the user's account is now in a locked state). Two
        // event types in AUDIT_EVENT_TYPES map to two distinct
        // downstream consumers: the auth event feeds anomaly
        // detection; the identity event feeds user-account history.
        await this.recordAuditEventUc.execute({
          userId: user.id.value,
          eventType: 'authentication.account.locked',
          payload: {
            reason: 'lockout_tier_triggered',
            lockedUntil: until.toISOString(),
            ipAddress: ip.value,
          },
          ipAddress: ip.value,
        });
        await this.recordAuditEventUc.execute({
          userId: user.id.value,
          eventType: 'identity.account.locked',
          payload: {
            reason: 'lockout_tier_triggered',
            lockedUntil: until.toISOString(),
          },
        });
        throw new DomainError(
          'authentication.account_locked',
          'Account temporarily locked due to repeated failed login attempts',
          { lockedUntil: until.toISOString() },
        );
      }

      // H-8: distributed lockout — 10 failures against this email from
      // ANY IPs within 15 minutes locks the account 15 minutes. A
      // single-IP attacker already tripped the tier lock above at 5;
      // this path catches the IP-rotating brute-forcer.
      const accountFailures = await this.recordAccountFailure(normalizedEmail);
      if (accountFailures !== null) {
        const until = new Date(
          this.clock.now().getTime() + ACCOUNT_LOCK_SECONDS * 1000,
        );
        const updatedCred = credential.lockUntil(this.clock, until);
        await this.txRunner.run(async (tx: Tx) => {
          await this.credentialRepo.save(tx, updatedCred);
        });
        await this.recordAuditEventUc.execute({
          userId: user.id.value,
          eventType: 'authentication.account.locked',
          payload: {
            reason: 'account_wide_threshold',
            failureCount: accountFailures,
            lockedUntil: until.toISOString(),
            ipAddress: ip.value,
          },
          ipAddress: ip.value,
        });
        await this.recordAuditEventUc.execute({
          userId: user.id.value,
          eventType: 'identity.account.locked',
          payload: {
            reason: 'account_wide_threshold',
            lockedUntil: until.toISOString(),
          },
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

    // Successful password — clear both failure windows and unlock the
    // credential happens in the tx below. H-8: the per-email any-IP
    // window is cleared here too, otherwise a user who recovers their
    // password stays one distributed burst away from another lock.
    await this.loginAttemptRepo.clear(normalizedEmail, ip.value);
    await this.loginAttemptRepo.clearAccount(normalizedEmail);

    // Determine if MFA is required. We do this by checking whether a
    // confirmed MfaSecret exists. (V1.5: handle the case where the user
    // has MFA but the second-factor verification hasn't completed yet.)
    const requiresMfa = await this.requiresMfa(user.id);

    // Audit fix C1: inline second factor. A valid TOTP code supplied
    // with the password completes the login in one round-trip.
    let mfaSatisfied = !requiresMfa;
    if (requiresMfa && input.mfaCode !== undefined && input.mfaCode !== '') {
      const ok = await this.verifyInlineMfa(user.id, input.mfaCode);
      if (!ok) {
        throw new DomainError(
          'identity.mfa.code_invalid',
          'Provided MFA code is invalid',
        );
      }
      mfaSatisfied = true;
    }
    const mfaRequired = requiresMfa && !mfaSatisfied;

    // H-12: throttle MFA-pending issuances. Each one is proof the
    // password was correct, so unbounded issuance is a
    // password-validation oracle. Over the limit → generic 401
    // (identical to a wrong password) + audit.
    if (mfaRequired) {
      const issuances = await this.loginAttemptRepo.recordMfaPendingIssuance(
        normalizedEmail,
        this.clock.now(),
        MFA_PENDING_WINDOW_SECONDS,
      );
      if (issuances > MFA_PENDING_ISSUANCE_LIMIT) {
        await this.recordAuditEventUc.execute({
          userId: user.id.value,
          eventType: 'authentication.login.throttled',
          payload: {
            reason: 'mfa_pending_issuance_limit',
            issuanceCount: issuances,
            emailFingerprint: fingerprintEmail(normalizedEmail),
            ipAddress: ip.value,
          },
          ipAddress: ip.value,
        });
        throw new DomainError(
          'authentication.invalid_credentials',
          'Invalid email or password',
        );
      }
    }

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
      // V1.5 (audit C-4): when the user has MFA enabled, the session
      // is created with mfaVerified=false. The user must call
      // POST /v1/identity/mfa/verify (presenting the mfaToken) before
      // any refresh/access token will be minted. When the inline
      // mfaCode was already verified, the session starts verified.
      requiresMfa: !mfaSatisfied,
    });

    const saved = await this.txRunner.run<{ session: Session }>(
      async (tx: Tx) => {
        // Unlock credential if it was previously locked (e.g. expired lock).
        const unlockedCred = credential.unlock(this.clock);
        await this.credentialRepo.save(tx, unlockedCred);
        const persisted = await this.sessionRepo.save(tx, session);
        // V1.5 outbox: append the event inside the same tx so the
        // relay re-publishes it post-commit. Crashing before the
        // relay runs leaves the event durably stored in the outbox
        // table — no dropped events.
        const event = new SessionCreated(
          this.idGenerator.generate(),
          this.clock.now(),
          persisted.id,
          persisted.userId,
          mfaRequired,
        );
        await this.outbox.append(tx, event);
        return { session: persisted };
      },
    );

    // Audit: authentication.login.succeeded.
    await this.recordAuditEventUc.execute({
      userId: saved.session.userId.value,
      eventType: 'authentication.login.succeeded',
      payload: {
        sessionId: saved.session.id.value,
        organizationSlug: saved.session.organizationId?.value ?? null,
        mfaRequired,
      },
    });

    let mfaToken: string | null = null;
    if (mfaRequired) {
      // Audit fix C1: record that this session is parked awaiting MFA
      // and mint the scoped pending token. No refresh token leaves
      // the use-case on this path.
      await this.recordAuditEventUc.execute({
        userId: saved.session.userId.value,
        eventType: 'authentication.mfa.required',
        payload: {
          sessionId: saved.session.id.value,
          outcome: 'pending_token_issued',
        },
      });
      mfaToken = await this.mintMfaPendingTokenUc.execute({
        userId: saved.session.userId.value,
        sessionId: saved.session.id.value,
      });
    }

    return {
      refreshToken: mfaRequired ? null : plaintextRefresh,
      mfaToken,
      sessionId: saved.session.id.value,
      userId: saved.session.userId.value,
      familyId: saved.session.familyId,
      expiresAt: saved.session.expiresAt,
      organizationId: saved.session.organizationId?.value ?? null,
      mfaRequired,
    };
  }

  /**
   * H-8 pre-check: throw when the per-email any-IP window has reached
   * the account-lock threshold within its window.
   */
  private assertAccountNotLocked(window: {
    count: number;
    lastFailureAt: Date | null;
  }): void {
    if (
      window.count < ACCOUNT_LOCK_THRESHOLD ||
      window.lastFailureAt === null
    ) {
      return;
    }
    const until = new Date(
      window.lastFailureAt.getTime() + ACCOUNT_LOCK_SECONDS * 1000,
    );
    if (until.getTime() <= this.clock.now().getTime()) {
      return;
    }
    throw new DomainError(
      'authentication.account_locked',
      'Account temporarily locked due to repeated failed login attempts',
      { lockedUntil: until.toISOString() },
    );
  }

  /**
   * H-8: record the failure in the per-email any-IP bucket. Returns
   * the resulting failure count when it has reached the account-lock
   * threshold (the caller locks the credential), null otherwise.
   */
  private async recordAccountFailure(email: string): Promise<number | null> {
    const window = await this.loginAttemptRepo.recordAccountFailure(
      email,
      this.clock.now(),
      ACCOUNT_LOCK_WINDOW_SECONDS,
    );
    if (window.count < ACCOUNT_LOCK_THRESHOLD) {
      return null;
    }
    return window.count;
  }

  /**
   * Audit fix C1: verify an inline 6-digit TOTP code against the
   * user's confirmed MFA secret, using the same TotpService the
   * dedicated verify endpoint uses (workstream B2 hardens that
   * service; both paths share it).
   */
  private async verifyInlineMfa(
    userId: UserId,
    code: string,
  ): Promise<boolean> {
    const trimmed = code.trim();
    if (!/^\d{6}$/.test(trimmed)) {
      return false;
    }
    const secret = await this.txRunner.run(async (tx: Tx) =>
      this.mfaSecretRepo.findById(tx, userId),
    );
    if (!secret || !secret.confirmed) {
      return false;
    }
    return secret.verifyTotpCode(trimmed, (s, c) => this.totp.verifyTotp(s, c));
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
    // enumeration leak in audit log either). The plaintext email is
    // NOT persisted (2026-10-19 audit MEDIUM): only a truncated
    // sha-256 fingerprint, matching the throttle guard's emailHash
    // convention, plus the IP.
    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'authentication.login.failed',
      payload: {
        emailFingerprint: fingerprintEmail(email),
        ipAddress: ip,
      },
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

/**
 * Truncated sha-256 of the normalized email — the same fingerprint
 * convention as ThrottleGuard.hashEmail. Lets security correlate
 * failed-login bursts across IPs without persisting PII.
 */
function fingerprintEmail(email: string): string {
  return createHash('sha256')
    .update(email.toLowerCase(), 'utf8')
    .digest('hex')
    .slice(0, 16);
}
