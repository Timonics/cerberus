import { Clock, DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { EmailVerificationConsumed } from '../events/engagement.events';

/**
 * Email-verification token.
 *
 * Each token is single-use. Issued by `RequestEmailVerificationUseCase`,
 * consumed by `ConfirmEmailVerificationUseCase`. Stored as a SHA-256
 * hash; the plaintext is returned to the caller exactly once at issue
 * time and never persisted.
 *
 * Invariants:
 *   * `expiresAt` MUST be in the future when `create()` is called.
 *   * Once `consumedAt` is set, the token is dead.
 *   * `consume()` is idempotent on already-consumed tokens.
 */
export class EmailVerification {
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
  }): EmailVerification {
    const now = params.clock.now();
    const expiresAt = new Date(now.getTime() + params.ttlSeconds * 1000);
    if (expiresAt.getTime() <= now.getTime()) {
      throw new DomainError(
        'domain.invariant_violation',
        'Email-verification token TTL must be positive',
      );
    }
    return new EmailVerification(
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
  }): EmailVerification {
    return new EmailVerification(
      params.id,
      params.userId,
      params.tokenHash,
      params.expiresAt,
      params.consumedAt,
      params.createdAt,
      [],
    );
  }

  /**
   * Mark the token consumed. Idempotent. Emits `EmailVerificationConsumed`.
   * The user-side effect (marking the User aggregate emailVerified) is
   * done by the use-case AFTER this returns the updated aggregate.
   */
  public consume(
    clock: Clock,
    eventIdGenerator: { generate(): string },
  ): EmailVerification {
    if (this.consumedAt !== null) {
      return this;
    }
    const now = clock.now();
    const event = new EmailVerificationConsumed(
      eventIdGenerator.generate(),
      now,
      this.userId.value,
      this.id,
    );
    return new EmailVerification(
      this.id,
      this.userId,
      this.tokenHash,
      this.expiresAt,
      now,
      this.createdAt,
      [...this.pendingEvents, event],
    );
  }

  /** True if the token is alive at the given time. */
  public isAliveAt(when: Date): boolean {
    if (this.consumedAt !== null) return false;
    return this.expiresAt.getTime() > when.getTime();
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}
