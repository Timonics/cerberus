import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
} from '../../../shared/domain';
import { UserId } from '../../domain/value-objects/user-id';
import { SessionId } from '../../../authentication/domain/value-objects/session-id';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import { TotpService } from '../../infrastructure/security/totp.service';
import * as argon2 from 'argon2';

export interface VerifySecondFactorInput {
  userId: string;
  /**
   * The session to mark MFA-verified. V1 supports at most one
   * session per user, but the use-case marks the named session
   * explicitly so we don't have to guess. The caller (REST verify
   * endpoint or OAuth password grant) supplies the sessionId that
   * came from the login response.
   */
  sessionId: string;
  /**
   * Either a 6-digit TOTP code (from the authenticator) OR a recovery
   * code (10 chars, Crockford-base32). The use-case detects which it is
   * by length.
   */
  code: string;
}

export interface VerifySecondFactorResult {
  matched: 'totp' | 'recovery';
  /** The session that was marked verified. */
  sessionId: string;
}

/**
 * Verify a second-factor code presented during login.
 *
 * The Authentication context calls this when a user has MFA enabled and
 * has successfully completed the first factor (password). Returns the
 * matched method so the caller can record which one was used.
 *
 * If neither a TOTP code nor a recovery code matches, throws
 * `identity.mfa.code_invalid` (TOTP) or `identity.mfa.recovery_code_invalid`
 * (recovery code). Both recovery-code failure modes — no match and
 * already used — return the SAME generic message (no oracle).
 *
 * Successful TOTP verification claims the current time step in Redis
 * (RFC 6238 §5.2 replay protection); the session is marked
 * MFA-verified only after the ownership check passes.
 */
@Injectable()
export class VerifySecondFactorUseCase {
  private readonly logger = new Logger(VerifySecondFactorUseCase.name);
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
    @Inject(SESSION_REPOSITORY)
    private readonly sessionRepo: SessionRepository,
    private readonly totp: TotpService,
  ) {}

  public async execute(
    input: VerifySecondFactorInput,
  ): Promise<VerifySecondFactorResult> {
    const userId = UserId.create(input.userId);
    const sessionId = SessionId.create(input.sessionId);
    const trimmed = input.code.trim();

    return this.txRunner.run(async (tx) => {
      const mfa = await this.mfaRepo.findById(tx, userId);
      if (!mfa || !mfa.confirmed) {
        throw new DomainError(
          'identity.mfa.not_enabled',
          'MFA is not enabled for this user',
        );
      }

      // TOTP codes are 6 digits; recovery codes are 10 Crockford chars.
      const looksLikeTotp = /^\d{6}$/.test(trimmed);
      const looksLikeRecovery = /^[0-9A-Z]{10}$/i.test(trimmed);

      if (looksLikeTotp) {
        // 2026-10-19 audit MEDIUM (TOTP replay): verify against the
        // current time step only (otplib default window 0) AND claim
        // the step in Redis so a code can't be replayed within its
        // validity window (RFC 6238 §5.2). The aggregate's sync
        // `verifyTotpCode` wrapper only adds the confirmed-check,
        // which is already enforced above, so we call the
        // replay-protected verifier directly here.
        const ok = await this.totp.verifyTotpFresh(
          userId.value,
          mfa.secret,
          trimmed,
        );
        if (ok) {
          // V1.7 audit fix #7: ownership check BEFORE the side-effect
          // (markMfaVerified). The caller's `userId` (from the JWT
          // principal at the controller) MUST own the session they're
          // trying to mark MFA-verified. Without this check, user A
          // with MFA enabled could mark user B's session as
          // MFA-verified, then chain with session-hijacking to bypass
          // MFA entirely. Same check applied to the recovery-code
          // branch below.
          const session = await this.sessionRepo.findById(tx, sessionId);
          if (!session || session.userId.value !== userId.value) {
            this.logger.warn(
              `mfa-verify ownership mismatch: caller=${userId.value} session=${sessionId.value} actual=${session?.userId.value ?? 'NOT_FOUND'}`,
            );
            throw new DomainError(
              'authentication.session.not_found',
              'Session not found or revoked',
            );
          }
          // V1.5 (audit C-4): mark the session as MFA-verified so the
          // OAuth password / refresh grants will mint an access token.
          // We look up by sessionId first; if the session is already
          // revoked or doesn't exist, throw — same shape as login.
          const verified = await this.sessionRepo.markMfaVerified(
            tx,
            sessionId,
          );
          if (!verified) {
            throw new DomainError(
              'authentication.session.not_found',
              'Session not found or revoked',
            );
          }
          return { matched: 'totp' as const, sessionId: input.sessionId };
        }
        throw new DomainError(
          'identity.mfa.code_invalid',
          'Provided TOTP code is invalid',
        );
      }

      if (looksLikeRecovery) {
        const result = await mfa.consumeRecoveryCode({
          plaintextCode: trimmed,
          verifyHash: async (plaintext, hash) => {
            try {
              return await argon2.verify(hash, plaintext);
            } catch {
              return false;
            }
          },
          now: new Date(),
        });
        if (result.matched) {
          // V1.7 audit fix #7: ownership check BEFORE the side-effects.
          const session = await this.sessionRepo.findById(tx, sessionId);
          if (!session || session.userId.value !== userId.value) {
            this.logger.warn(
              `mfa-verify ownership mismatch (recovery): caller=${userId.value} session=${sessionId.value} actual=${session?.userId.value ?? 'NOT_FOUND'}`,
            );
            throw new DomainError(
              'authentication.session.not_found',
              'Session not found or revoked',
            );
          }
          await this.mfaRepo.save(tx, result.updated);
          // V1.5 (audit C-4): same — mark session verified.
          const verified = await this.sessionRepo.markMfaVerified(
            tx,
            sessionId,
          );
          if (!verified) {
            throw new DomainError(
              'authentication.session.not_found',
              'Session not found or revoked',
            );
          }
          return {
            matched: 'recovery' as const,
            sessionId: input.sessionId,
          };
        }
        // 2026-10-19 audit LOW: "wrong" vs "used" recovery codes now
        // return one generic message — distinguishing them was an
        // oracle that told an attacker they had guessed a valid code.
        throw new DomainError(
          'identity.mfa.recovery_code_invalid',
          'Recovery code is invalid',
        );
      }

      throw new DomainError(
        'identity.mfa.code_invalid',
        'Code format is invalid',
      );
    });
  }
}
