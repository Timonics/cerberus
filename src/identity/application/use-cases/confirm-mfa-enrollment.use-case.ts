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
} from '../../../shared/domain';
import { UserId } from '../../domain/value-objects/user-id';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import { TotpService } from '../../infrastructure/security/totp.service';

export interface ConfirmMfaEnrollmentInput {
  userId: string;
  code: string;
}

/**
 * Confirm MFA enrollment with the first TOTP code.
 *
 * Loads the pending MfaSecret, verifies the provided code against it,
 * marks the secret as confirmed, and emits `MfaEnabled`.
 */
@Injectable()
export class ConfirmMfaEnrollmentUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
    private readonly totp: TotpService,
  ) {}

  public async execute(input: ConfirmMfaEnrollmentInput): Promise<void> {
    const userId = UserId.create(input.userId);

    const events = await this.txRunner.run(async (tx) => {
      const mfa = await this.mfaRepo.findById(tx, userId);
      if (!mfa) {
        throw new DomainError(
          'identity.mfa.not_enabled',
          'No MFA enrollment in progress for this user',
        );
      }

      const updated = mfa.confirmEnrollment({
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
        code: input.code,
        verifyTotp: (secret, code) => this.totp.verifyTotp(secret, code),
      });
      await this.mfaRepo.save(tx, updated);
      return updated.pullDomainEvents();
    });

    await this.eventBus.publishAll(events);

    // Audit: identity.mfa.enabled.
    await this.recordAuditEventUc.execute({
      userId: input.userId,
      eventType: 'identity.mfa.enabled',
      payload: {},
    });
  }
}
