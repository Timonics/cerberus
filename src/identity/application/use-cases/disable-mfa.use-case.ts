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

export interface DisableMfaInput {
  userId: string;
  code: string;
}

/**
 * Disable MFA entirely.
 *
 * Requires a fresh TOTP code as confirmation — this protects against an
 * attacker who has the session cookie but not the authenticator.
 * Deletes the secret row + all recovery codes via the FK cascade.
 */
@Injectable()
export class DisableMfaUseCase {
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

  public async execute(input: DisableMfaInput): Promise<void> {
    const userId = UserId.create(input.userId);

    const events = await this.txRunner.run(async (tx) => {
      const mfa = await this.mfaRepo.findById(tx, userId);
      if (!mfa) {
        throw new DomainError(
          'identity.mfa.not_enabled',
          'MFA is not enabled for this user',
        );
      }

      // Verify the user has a working authenticator before turning MFA off.
      if (
        !mfa.verifyTotpCode(input.code, (s, c) => this.totp.verifyTotp(s, c))
      ) {
        throw new DomainError(
          'identity.mfa.code_invalid',
          'Provided TOTP code does not match',
        );
      }

      const { events } = mfa.disable({
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
      });
      await this.mfaRepo.delete(tx, userId);
      return events;
    });

    await this.eventBus.publishAll(events);

    // Audit: identity.mfa.disabled.
    await this.recordAuditEventUc.execute({
      userId: input.userId,
      eventType: 'identity.mfa.disabled',
      payload: { actor: 'self' },
    });
  }
}
