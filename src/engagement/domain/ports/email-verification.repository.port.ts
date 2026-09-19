import { Tx } from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { EmailVerification } from '../aggregates/email-verification';

export abstract class EmailVerificationRepository {
  public abstract findByTokenHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<EmailVerification | null>;

  public abstract findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<EmailVerification | null>;

  public abstract save(
    tx: Tx,
    verification: EmailVerification,
  ): Promise<EmailVerification>;

  public abstract delete(tx: Tx, id: string): Promise<void>;
}

export const EMAIL_VERIFICATION_REPOSITORY = Symbol(
  'EmailVerificationRepository',
);
