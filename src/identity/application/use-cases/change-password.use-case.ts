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
import { Password } from '../../../shared/domain/value-objects/password';
import {
  PASSWORD_HASHER,
  PasswordHash,
  PasswordHasher,
} from '../../../shared/domain/value-objects/password-hash';
import { Credential } from '../../domain/aggregates/credential';
import { UserId } from '../../domain/value-objects/user-id';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../domain/ports/credential.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';

export interface ChangePasswordInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

/**
 * Change a user's password.
 *
 * Verifies the current password against the stored hash before allowing
 * the change. Atomic: the credential row is updated inside a transaction.
 *
 * Emits `PasswordChanged` so the Authentication context can revoke all
 * live sessions for this user (defensive — if an attacker has the old
 * password, rotating it kicks them out everywhere).
 */
@Injectable()
export class ChangePasswordUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(PASSWORD_HASHER) private readonly passwordHasher: PasswordHasher,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(CREDENTIAL_REPOSITORY)
    private readonly credentialRepo: CredentialRepository,
  ) {}

  public async execute(input: ChangePasswordInput): Promise<void> {
    const userId = UserId.create(input.userId);
    const newPassword = Password.create(input.newPassword);

    // Hash the new password outside the transaction.
    const newHashString = await this.passwordHasher.hash(
      newPassword.toHashableString(),
    );
    const newPasswordHash = PasswordHash.fromHashString(newHashString);
    newPassword.dispose();

    const events = await this.txRunner.run(async (tx) => {
      const user = await this.userRepo.findById(tx, userId);
      if (!user) {
        throw new DomainError(
          'identity.user.not_found',
          'User does not exist',
          { userId: userId.value },
        );
      }
      const credential = await this.credentialRepo.findById(tx, userId);
      if (!credential) {
        throw new DomainError(
          'identity.user.not_found',
          'User has no credential',
          { userId: userId.value },
        );
      }

      // Verify the current password. If this fails we throw — never
      // reveal in the response whether it was the user or the credential
      // that was missing.
      const currentOk = await this.passwordHasher.verify(
        input.currentPassword,
        credential.passwordHash.value,
      );
      if (!currentOk) {
        throw new DomainError(
          'authentication.invalid_credentials',
          'Current password is incorrect',
        );
      }

      // Reject reuse — at minimum, a different password. (Full password
      // history is a V2 feature.)
      if (credential.passwordHash.equals(newPasswordHash)) {
        throw new DomainError(
          'identity.password.reused',
          'New password must be different from the current password',
        );
      }

      const updated = credential.changePassword({
        clock: this.clock,
        eventIdGenerator: this.idGenerator,
        newPasswordHash,
      });
      await this.credentialRepo.save(tx, updated);
      return updated.pullDomainEvents();
    });

    await this.eventBus.publishAll(events);
  }
}
