import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
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
} from '../../../shared/domain';
import { MfaSecret, RecoveryCode } from '../../domain/aggregates/mfa-secret';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';
import { TotpService } from '../../infrastructure/security/totp.service';

export interface EnableMfaInput {
  userId: string;
}

/**
 * Result of `EnableMfaUseCase`.
 *
 * `otpAuthUrl` is the URI the user's authenticator app scans (rendered
 * as a QR code by the client). `secret` is the raw base32 secret
 * (shown once for manual entry). `recoveryCodes` is the list of
 * plaintext codes — shown EXACTLY ONCE in the response and never again.
 */
export interface EnableMfaResult {
  otpAuthUrl: string;
  secret: string;
  recoveryCodes: string[];
}

/**
 * Begin MFA enrollment for a user.
 *
 * Generates a fresh TOTP secret + 10 recovery codes, stores the hashed
 * versions, and returns the plaintext values to the caller. The user
 * confirms enrollment in a second call (`ConfirmMfaEnrollmentUseCase`)
 * by providing a valid TOTP code.
 *
 * Returns `MfaSecret.confirmed = false` after this call; until
 * confirmation, the secret cannot be used to authenticate.
 *
 * Throws `identity.mfa.already_enabled` if the user already has a
 * confirmed MFA secret.
 */
@Injectable()
export class EnableMfaUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
    private readonly totp: TotpService,
  ) {}

  public async execute(input: EnableMfaInput): Promise<EnableMfaResult> {
    const userId = UserId.create(input.userId);
    const secret = this.totp.generateSecret();
    const plaintextCodes = this.totp.generateRecoveryCodes(10);

    // Hash recovery codes for storage.
    const recoveryCodeRows: RecoveryCode[] = [];
    for (const plaintext of plaintextCodes) {
      const codeHash = await argon2.hash(plaintext, {
        type: argon2.argon2id,
        memoryCost: 19_456, // OWASP minimum for recovery codes (lower than password)
        timeCost: 2,
        parallelism: 1,
      });
      recoveryCodeRows.push(
        RecoveryCode.create({
          id: this.idGenerator.generate(),
          mfaSecretId: '', // filled below once we have the secret row's ID
          codeHash,
        }),
      );
    }

    const { events, result } = await this.txRunner.run(async (tx) => {
      const user = await this.userRepo.findById(tx, userId);
      if (!user) {
        throw new DomainError(
          'identity.user.not_found',
          'User does not exist',
          { userId: userId.value },
        );
      }
      const existing = await this.mfaRepo.findById(tx, userId);
      if (existing && existing.confirmed) {
        throw new DomainError(
          'identity.mfa.already_enabled',
          'MFA is already enabled for this user',
        );
      }

      // Mint the secret row's ID first so we can backfill the
      // recovery-code FK. We use a UUID so the secret row exists in
      // memory before the FK is set.
      const mfaSecretId = this.idGenerator.generate();
      const withSecretId = recoveryCodeRows.map((rc) =>
        RecoveryCode.create({
          id: rc.id,
          mfaSecretId, // now set
          codeHash: rc.codeHash,
        }),
      );

      const mfaSecret = MfaSecret.enroll({
        id: mfaSecretId,
        userId,
        secret,
        recoveryCodes: withSecretId,
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
      });
      await this.mfaRepo.save(tx, mfaSecret);

      return {
        events: mfaSecret.pullDomainEvents(),
        result: {
          secret,
          otpAuthUrl: this.totp.buildOtpAuthUrl({
            secret,
            accountName: user.email.value,
            issuer: 'Cerberus',
          }),
          recoveryCodes: plaintextCodes,
        },
      };
    });

    await this.eventBus.publishAll(events);
    return result;
  }
}

// Suppress unused-import warning for crypto module — kept for parity with
// the ID generator convention.
void randomUUID;
