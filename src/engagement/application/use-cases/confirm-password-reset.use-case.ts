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
  PasswordHash,
  PasswordHasher,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Password } from '../../../shared/domain/value-objects/password';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../../identity/domain/ports/credential.repository.port';
import {
  PASSWORD_RESET_REPOSITORY,
  PasswordResetRepository,
} from '../../domain/ports/password-reset.repository.port';
import { Sha256TokenService } from '../../infrastructure/security/sha256-token.service';
import { RecordAuditEventUseCase } from './record-audit-event.use-case';

export interface ConfirmPasswordResetInput {
  token: string;
  newPassword: string;
}

/**
 * Redeem a password-reset token and rotate the credential.
 *
 * The token is verified (lookup + expiry + not-already-consumed). The
 * credential's password hash is rotated atomically with the token's
 * mark-consumed. The cross-context event listener in Authentication
 * (`PasswordChangedSessionRevoker`) will mass-revoke all the user's
 * sessions after this commit.
 *
 * Throws:
 *   - `engagement.password_reset.invalid_token` — token not found.
 *   - `engagement.password_reset.expired` — token past `expiresAt`.
 *   - `identity.password.too_weak` — new password fails the policy
 *     (enforced here so the GraphQL path, which has no DTO bound, is
 *     covered too).
 *
 * Audits `identity.password.reset` after the rotation commits.
 */
@Injectable()
export class ConfirmPasswordResetUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(PASSWORD_RESET_REPOSITORY)
    private readonly resetRepo: PasswordResetRepository,
    @Inject(CREDENTIAL_REPOSITORY)
    private readonly credentialRepo: CredentialRepository,
    @Inject(PASSWORD_HASHER) private readonly passwordHasher: PasswordHasher,
    private readonly tokenService: Sha256TokenService,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(input: ConfirmPasswordResetInput): Promise<void> {
    const tokenHash = this.tokenService.hash(input.token);

    // 2026-10-19 audit MEDIUM: enforce the password policy at the
    // use-case boundary. The REST DTO bounds length, but the GraphQL
    // input has no bound at all — without this, a reset could rotate
    // to a 1-char password.
    const newPassword = Password.create(input.newPassword);

    const { events, userId } = await this.txRunner.run<{
      events: unknown[];
      userId: string;
    }>(async (tx: Tx) => {
      const reset = await this.resetRepo.findByTokenHash(tx, tokenHash);
      if (!reset) {
        throw new DomainError(
          'engagement.password_reset.invalid_token',
          'Password-reset token is not valid',
        );
      }
      if (!reset.isAliveAt(this.clock.now())) {
        throw new DomainError(
          'engagement.password_reset.expired',
          'Password-reset token has expired',
        );
      }

      const credential = await this.credentialRepo.findById(tx, reset.userId);
      if (!credential) {
        throw new DomainError(
          'identity.user.not_found',
          'No credential for this user',
        );
      }

      const newHashString = await this.passwordHasher.hash(
        newPassword.toHashableString(),
      );
      newPassword.dispose();
      const newHash = PasswordHash.fromHashString(newHashString);

      const consumed = reset.consume(this.clock, this.idGenerator);
      const savedReset = await this.resetRepo.save(tx, consumed);

      const updated = credential.changePassword({
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
        newPasswordHash: newHash,
      });
      await this.credentialRepo.save(tx, updated);

      return {
        events: [
          ...savedReset.pullDomainEvents(),
          ...updated.pullDomainEvents(),
        ],
        userId: credential.userId.value,
      };
    });

    await this.eventBus.publishAll(events as never);

    // 2026-10-19 audit MEDIUM: the credential rotation itself was
    // never audited (only the token request/consumption). Write
    // `identity.password.reset` so account-history shows the rotation.
    await this.recordAuditEventUc.execute({
      userId,
      eventType: 'identity.password.reset',
      payload: {},
    });
  }
}
