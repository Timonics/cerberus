import { Clock, DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { PasswordResetConsumed } from '../events/engagement.events';

/**
 * Password-reset token.
 *
 * Same shape as `EmailVerification` (single-use, hash-stored, time-
 * bound) but bound to a different action: redeeming one calls
 * `Credential.changePassword()`.
 *
 * Invariants:
 *   * One token per redemption. `consume()` is idempotent on already-
 *     consumed tokens.
 *   * `expiresAt` MUST be in the future when created.
 */
export class PasswordReset {
  private constructor(
    public readonly id: string,
    public readonly userId: UserId,
    public readonly tokenHash: string,
    public readonly expiresAt: Date,
    public readonly consumedAt: Date | null,
    public readonly createdAt: Date,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  public static create(params: {
    id: string;
    userId: UserId;
    tokenHash: string;
    clock: Clock;
    ttlSeconds: number;
  }): PasswordReset {
    const now = params.clock.now();
    const expiresAt = new Date(now.getTime() + params.ttlSeconds * 1000);
    if (expiresAt.getTime() <= now.getTime()) {
      throw new DomainError(
        'domain.invariant_violation',
        'Password-reset token TTL must be positive',
      );
    }
    return new PasswordReset(
      params.id,
      params.userId,
      params.tokenHash,
      expiresAt,
      null,
      now,
      [],
    );
  }

  public static fromPersistence(params: {
    id: string;
    userId: UserId;
    tokenHash: string;
    expiresAt: Date;
    consumedAt: Date | null;
    createdAt: Date;
  }): PasswordReset {
    return new PasswordReset(
      params.id,
      params.userId,
      params.tokenHash,
      params.expiresAt,
      params.consumedAt,
      params.createdAt,
      [],
    );
  }

  public consume(
    clock: Clock,
    eventIdGenerator: { generate(): string },
  ): PasswordReset {
    if (this.consumedAt !== null) {
      return this;
    }
    const now = clock.now();
    const event = new PasswordResetConsumed(
      eventIdGenerator.generate(),
      now,
      this.userId.value,
      this.id,
    );
    return new PasswordReset(
      this.id,
      this.userId,
      this.tokenHash,
      this.expiresAt,
      now,
      this.createdAt,
      [...this.pendingEvents, event],
    );
  }

  public isAliveAt(when: Date): boolean {
    if (this.consumedAt !== null) return false;
    return this.expiresAt.getTime() > when.getTime();
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}
