import { Tx } from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { PasswordReset } from '../aggregates/password-reset';

export abstract class PasswordResetRepository {
  public abstract findByTokenHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<PasswordReset | null>;

  public abstract findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<PasswordReset | null>;

  public abstract save(tx: Tx, reset: PasswordReset): Promise<PasswordReset>;

  public abstract delete(tx: Tx, id: string): Promise<void>;
}

export const PASSWORD_RESET_REPOSITORY = Symbol('PasswordResetRepository');
