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
import { User } from '../../../identity/domain/aggregates/user';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../../identity/domain/ports/user.repository.port';
import { EmailVerification } from '../../domain/aggregates/email-verification';
import {
  EMAIL_VERIFICATION_REPOSITORY,
  EmailVerificationRepository,
} from '../../domain/ports/email-verification.repository.port';
import { Sha256TokenService } from '../../infrastructure/security/sha256-token.service';
import { RecordAuditEventUseCase } from './record-audit-event.use-case';

export interface ConfirmEmailVerificationInput {
  token: string;
}

/**
 * Redeem an email-verification token.
 *
 * Hashes the presented plaintext, looks up by hash, validates the
 * token is unconsumed + unexpired, marks it consumed, and updates the
 * User aggregate to set `emailVerifiedAt`.
 *
 * On any failure (token not found, expired, already consumed), throws
 * a domain error with a stable code. The user sees the same generic
 * message regardless of which case it was (no enumeration of which
 * tokens exist).
 *
 * Atomicity: the verification mark-consumed + user mark-verified
 * happen in a single transaction.
 */
@Injectable()
export class ConfirmEmailVerificationUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(EMAIL_VERIFICATION_REPOSITORY)
    private readonly verifRepo: EmailVerificationRepository,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    private readonly tokenService: Sha256TokenService,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(input: ConfirmEmailVerificationInput): Promise<void> {
    const tokenHash = this.tokenService.hash(input.token);

    const result = await this.txRunner.run<{
      user: User;
      verification: EmailVerification;
      wasAlreadyVerified: boolean;
    } | null>(async (tx: Tx) => {
      const verification = await this.verifRepo.findByTokenHash(tx, tokenHash);
      if (!verification || !verification.isAliveAt(this.clock.now())) {
        return null;
      }
      const user = await this.userRepo.findById(tx, verification.userId);
      if (!user) {
        return null;
      }
      const wasAlreadyVerified = user.emailVerifiedAt !== null;
      const consumed = verification.consume(this.clock, this.idGenerator);
      const savedVerif = await this.verifRepo.save(tx, consumed);
      const verifiedUser = user.markEmailVerified(this.clock);
      const savedUser = await this.userRepo.save(tx, verifiedUser);
      return { user: savedUser, verification: savedVerif, wasAlreadyVerified };
    });

    if (!result) {
      throw new DomainError(
        'engagement.email_verification.invalid_token',
        'Email verification token is not valid',
      );
    }

    await this.eventBus.publishAll(result.verification.pullDomainEvents());

    // V1.5 audit: write `identity.email.verified` only on the
    // null→set transition. `User.markEmailVerified` is idempotent —
    // re-presenting a valid token after the email is already
    // verified should NOT double-fire the audit event.
    if (!result.wasAlreadyVerified) {
      await this.recordAuditEventUc.execute({
        userId: result.user.id.value,
        eventType: 'identity.email.verified',
        payload: {
          verificationId: result.verification.id,
        },
      });
    }
  }
}
