import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import {
  CLOCK,
  Clock,
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';
import { RefreshTokenHash } from '../../../authentication/domain/value-objects/refresh-token-hash';
import { SessionId } from '../../../authentication/domain/value-objects/session-id';
import { IssueAccessTokenUseCase } from '../../../authorization/application/use-cases/issue-access-token.use-case';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  MFA_ATTEMPT_TRACKER,
  MfaAttemptTracker,
} from '../../domain/ports/mfa-attempt-tracker.port';
import { VerifySecondFactorUseCase } from './verify-second-factor.use-case';

export interface CompleteMfaVerificationInput {
  userId: string;
  sessionId: string;
  code: string;
}

export interface CompleteMfaVerificationResult {
  accessToken: string;
  refreshToken: string;
  mfaVerified: true;
}

/** Failure count within the window that triggers a lockout. */
export const MFA_MAX_FAILURES = 5;
/** Lockout duration after `MFA_MAX_FAILURES` failures (15 minutes). */
export const MFA_LOCKOUT_SECONDS = 15 * 60;

/**
 * Thrown when the (userId, sessionId) pair is MFA-locked. The
 * controller maps this to a 401 `identity.mfa.locked` response. It is
 * a plain Error (not DomainError) because the shared DomainError code
 * union lives outside this bounded context.
 */
export class MfaLockedError extends Error {
  public constructor() {
    super('Too many failed MFA verification attempts; try again later');
    this.name = 'MfaLockedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Complete an MFA login (audit 2026-10-19 fixes C1 + H-5b).
 *
 * Wraps `VerifySecondFactorUseCase` with the controls the raw verifier
 * deliberately does not own:
 *
 *   1. Rate-limit companion: per-(userId, sessionId) Redis failure
 *      counter. 5 failures within 15 minutes lock the pair out for 15
 *      minutes (`identity.mfa.locked`). Ownership errors and
 *      "MFA not enabled" do NOT count toward the lockout — only actual
 *      code failures do.
 *   2. Audit BOTH outcomes: `identity.mfa.verified` and
 *      `identity.mfa.verification_failed`.
 *   3. Token issuance: the caller presents EITHER a normal access JWT
 *      OR an `mfa:verify`-scoped pending token (see
 *      `MfaVerifyGuard`); either way, on success we mint the real
 *      token pair so the login completes in one round-trip:
 *      an access token via `IssueAccessTokenUseCase` and a fresh
 *      refresh token rotated onto the pending session (the hash minted
 *      at login belonged to a plaintext that was never disclosed, so
 *      rotating here is safe and revokes nothing else).
 */
@Injectable()
export class CompleteMfaVerificationUseCase {
  private readonly logger = new Logger(CompleteMfaVerificationUseCase.name);

  public constructor(
    @Inject(MFA_ATTEMPT_TRACKER)
    private readonly attempts: MfaAttemptTracker,
    private readonly verifySecondFactorUc: VerifySecondFactorUseCase,
    private readonly issueAccessTokenUc: IssueAccessTokenUseCase,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
    @Inject(SESSION_REPOSITORY)
    private readonly sessionRepo: SessionRepository,
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  public async execute(
    input: CompleteMfaVerificationInput,
  ): Promise<CompleteMfaVerificationResult> {
    const { userId, sessionId, code } = input;

    if (await this.attempts.isLocked(userId, sessionId)) {
      throw new MfaLockedError();
    }

    let matched: 'totp' | 'recovery';
    try {
      const result = await this.verifySecondFactorUc.execute({
        userId,
        sessionId,
        code,
      });
      matched = result.matched;
    } catch (err) {
      if (this.isCodeFailure(err)) {
        const failureCount = await this.attempts.recordFailure(
          userId,
          sessionId,
        );
        await this.recordAuditEventUc.execute({
          userId,
          eventType: 'identity.mfa.verification_failed',
          payload: { sessionId, failureCount },
        });
        if (failureCount >= MFA_MAX_FAILURES) {
          await this.attempts.lock(userId, sessionId, MFA_LOCKOUT_SECONDS);
          this.logger.warn(
            `MFA verification locked for userId=${userId} sessionId=${sessionId} after ${failureCount} failures`,
          );
          throw new MfaLockedError();
        }
      }
      throw err;
    }

    await this.attempts.clearFailures(userId, sessionId);
    await this.recordAuditEventUc.execute({
      userId,
      eventType: 'identity.mfa.verified',
      payload: { sessionId, matched },
    });

    // Rotate a fresh refresh token onto the pending session so the
    // caller can use /v1/auth/refresh from here on. Atomic
    // compare-and-swap: if another rotation landed first we fail
    // closed rather than silently clobbering it.
    const plaintextRefresh = randomBytes(32).toString('base64url');
    const newHash = await RefreshTokenHash.fromPlaintext(plaintextRefresh);
    const sessionIdVo = SessionId.create(sessionId);

    await this.txRunner.run(async (tx: Tx) => {
      const session = await this.sessionRepo.findById(tx, sessionIdVo);
      if (!session || !session.isAliveAt(this.clock.now())) {
        throw new DomainError(
          'authentication.session.not_found',
          'Session not found or revoked',
        );
      }
      const rotated = session.rotateRefreshToken({
        newRefreshHash: newHash,
        clock: this.clock,
        // Verification must not extend the session's lifetime.
        newExpiresAt: session.expiresAt,
      });
      const swapped = await this.sessionRepo.rotateRefreshTokenAtomic(
        tx,
        session.refreshHash.value,
        {
          refreshHash: newHash.value,
          expiresAt: rotated.expiresAt,
          lastUsedAt: rotated.lastUsedAt ?? this.clock.now(),
          lastRotatedAt: rotated.lastRotatedAt ?? this.clock.now(),
          previousRefreshHashes: rotated.previousRefreshHashes,
        },
      );
      if (!swapped) {
        throw new DomainError(
          'authentication.session.not_found',
          'Session not found or revoked',
        );
      }
    });

    const issued = await this.issueAccessTokenUc.execute({ userId });

    return {
      accessToken: issued.accessToken,
      refreshToken: plaintextRefresh,
      mfaVerified: true,
    };
  }

  /** Only genuine code failures count toward lockout. */
  private isCodeFailure(err: unknown): boolean {
    return (
      err instanceof DomainError &&
      (err.code === 'identity.mfa.code_invalid' ||
        err.code === 'identity.mfa.recovery_code_invalid')
    );
  }
}
