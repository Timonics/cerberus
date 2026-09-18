import { Inject, Injectable } from '@nestjs/common';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
} from '../../../shared/domain';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import { TotpService } from '../../infrastructure/security/totp.service';
import * as argon2 from 'argon2';

export interface VerifySecondFactorInput {
  userId: string;
  /**
   * Either a 6-digit TOTP code (from the authenticator) OR a recovery
   * code (10 chars, Crockford-base32). The use-case detects which it is
   * by length.
   */
  code: string;
}

export interface VerifySecondFactorResult {
  matched: 'totp' | 'recovery';
}

/**
 * Verify a second-factor code presented during login.
 *
 * The Authentication context calls this when a user has MFA enabled and
 * has successfully completed the first factor (password). Returns the
 * matched method so the caller can record which one was used.
 *
 * If neither a TOTP code nor a recovery code matches, throws
 * `identity.mfa.code_invalid` (or `identity.mfa.recovery_code_invalid`
 * if a recovery code was attempted but already used).
 */
@Injectable()
export class VerifySecondFactorUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
    private readonly totp: TotpService,
  ) {}

  public async execute(
    input: VerifySecondFactorInput,
  ): Promise<VerifySecondFactorResult> {
    const userId = UserId.create(input.userId);
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
        const ok = mfa.verifyTotpCode(trimmed, (s, c) =>
          this.totp.verifyTotp(s, c),
        );
        if (ok) {
          return { matched: 'totp' as const };
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
          await this.mfaRepo.save(tx, result.updated);
          return { matched: 'recovery' as const };
        }
        if (result.alreadyUsed) {
          throw new DomainError(
            'identity.mfa.recovery_code_invalid',
            'Recovery code has already been used',
          );
        }
        throw new DomainError(
          'identity.mfa.recovery_code_invalid',
          'Recovery code does not match',
        );
      }

      throw new DomainError(
        'identity.mfa.code_invalid',
        'Code format is invalid',
      );
    });
  }
}
