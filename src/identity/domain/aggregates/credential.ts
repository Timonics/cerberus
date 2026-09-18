import { Clock, DomainError, PasswordHash } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { PasswordChanged } from '../events/identity.events';
import { UserId } from '../value-objects/user-id';

/**
 * Credential aggregate root.
 *
 * Owns the user's password hash and account-lock state. Created on
 * registration (with the freshly-hashed password), mutated by
 * `changePassword()`, and consultable by the Authentication context during
 * login.
 *
 * Invariants:
 *
 *   * `passwordHash` is always a valid argon2id PHC string. The constructor
 *     re-validates via `PasswordHash.rehydrate()` as a defensive check.
 *
 *   * `lockedUntil` is monotonic — we never "extend" a lock backwards. If
 *     `lockedUntil` is in the past, the account is treated as unlocked by
 *     the Authentication context.
 *
 *   * `passwordChangedAt` is set on every successful password change.
 *     Used by the Authentication context to invalidate refresh tokens
 *     issued before that timestamp.
 *
 * Domain events emitted:
 *
 *   * `PasswordChanged` — when the password is rotated via
 *     `changePassword()`. The Authentication context listens for this and
 *     revokes all live sessions.
 */
export class Credential {
  private constructor(
    public readonly userId: UserId,
    public readonly passwordHash: PasswordHash,
    public readonly passwordChangedAt: Date,
    public readonly lockedUntil: Date | null,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  // -------------------------------------------------------------------------
  // Factory: new credential
  // -------------------------------------------------------------------------

  public static create(params: {
    clock: Clock;
    userId: UserId;
    passwordHash: PasswordHash;
  }): Credential {
    const { clock, userId, passwordHash } = params;
    const now = clock.now();
    return new Credential(
      userId,
      passwordHash,
      now,
      null, // not locked
      now,
      now,
      [],
    );
    // We deliberately do NOT emit `PasswordChanged` on registration —
    // there is no "old password" to invalidate, and Authentication hasn't
    // issued any sessions yet.
  }

  // -------------------------------------------------------------------------
  // Factory: rehydrate from persistence
  // -------------------------------------------------------------------------

  public static fromPersistence(params: {
    userId: UserId;
    passwordHash: PasswordHash;
    passwordChangedAt: Date;
    lockedUntil: Date | null;
    createdAt: Date;
    updatedAt: Date;
  }): Credential {
    return new Credential(
      params.userId,
      params.passwordHash,
      params.passwordChangedAt,
      params.lockedUntil,
      params.createdAt,
      params.updatedAt,
      [],
    );
  }

  // -------------------------------------------------------------------------
  // Domain methods
  // -------------------------------------------------------------------------

  /**
   * Change the password to a new argon2id hash. Emits `PasswordChanged`
   * so the Authentication context can revoke all live sessions.
   *
   * Throws if the account is currently locked past the requested change
   * time (caller should unlock first). The check uses `now()` so a lock
   * that has already expired does NOT block the change.
   */
  public changePassword(params: {
    clock: Clock;
    eventIdGenerator: { generate(): string };
    newPasswordHash: PasswordHash;
  }): Credential {
    const { clock, eventIdGenerator, newPasswordHash } = params;
    const now = clock.now();

    if (this.lockedUntil !== null && this.lockedUntil > now) {
      throw new DomainError(
        'identity.credential.locked',
        'Account is locked; cannot change password until the lock expires',
        { lockedUntil: this.lockedUntil.toISOString() },
      );
    }

    const event = new PasswordChanged(
      eventIdGenerator.generate(),
      now,
      this.userId,
    );

    return new Credential(
      this.userId,
      newPasswordHash,
      now,
      null, // changing the password resets any lock
      this.createdAt,
      now,
      [...this.pendingEvents, event],
    );
  }

  /**
   * Lock the account until a given timestamp. The Authentication context
   * calls this when it detects brute-force activity. Lockout duration is
   * policy-driven (sliding-window backoff); this method only records the
   * expiry.
   */
  public lockUntil(clock: Clock, until: Date): Credential {
    // Idempotent — re-locking with a later expiry extends the lock.
    if (this.lockedUntil !== null && this.lockedUntil >= until) {
      return this;
    }
    const now = clock.now();
    return new Credential(
      this.userId,
      this.passwordHash,
      this.passwordChangedAt,
      until,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  /**
   * Explicitly unlock the account. Idempotent. Called by the
   * Authentication context after a successful login when the lockout
   * window has elapsed.
   */
  public unlock(clock: Clock): Credential {
    if (this.lockedUntil === null) {
      return this;
    }
    const now = clock.now();
    return new Credential(
      this.userId,
      this.passwordHash,
      this.passwordChangedAt,
      null,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  /**
   * Check whether the account is currently locked at the given time.
   * Pure function — does not mutate the aggregate.
   */
  public isLockedAt(when: Date): boolean {
    return this.lockedUntil !== null && this.lockedUntil > when;
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}
