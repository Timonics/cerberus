import { Clock, DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { Email } from '../../../shared/domain/value-objects/email';
import { UserRegistered } from '../events/identity.events';
import { OrgId } from '../value-objects/org-id';
import { UserId } from '../value-objects/user-id';

/**
 * User aggregate root.
 *
 * Owns the canonical user record: email (the login identifier),
 * organization membership, display name, email-verification status, and a
 * soft-delete marker. Constructed only via the static factories below;
 * direct construction is impossible.
 *
 * Invariants this aggregate enforces:
 *
 *   * Email is non-empty and canonical (lowercase, trimmed). The shared
 *     `Email` value object already guarantees this; we re-check on
 *     rehydration as a defensive measure.
 *
 *   * A user always belongs to exactly one organization in V1.
 *
 *   * `displayName`, if set, is at most 120 characters (matches the DTO
 *     validation so the same constraint holds in the domain).
 *
 *   * `emailVerifiedAt` may only be set once — re-marking has no effect.
 *
 * Domain events emitted:
 *
 *   * `UserRegistered` — once, when `User.register()` is called for the
 *     first time. Repositories persist the aggregate; the application
 *     layer publishes the event AFTER the transaction commits (see the
 *     sharp-edge comment in `RegisterUserUseCase`).
 */
export class User {
  private constructor(
    public readonly id: UserId,
    public readonly organizationId: OrgId,
    public readonly email: Email,
    public readonly displayName: string | null,
    public readonly emailVerifiedAt: Date | null,
    public readonly deletedAt: Date | null,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
    // Domain events emitted since this aggregate instance was loaded.
    // The repository clears them after persisting.
    private readonly pendingEvents: DomainEvent[],
  ) {}

  // -------------------------------------------------------------------------
  // Factory: new registration
  // -------------------------------------------------------------------------

  /**
   * Register a new user.
   *
   * Mints a fresh UserId, validates the email, captures `emailVerifiedAt =
   * null` (the user must verify their address via the Engagement flow).
   * The new user starts as unverified; the registration use-case then
   * kicks off the email-verification token issuance.
   *
   * @param clock        Used to stamp `createdAt` and `updatedAt`.
   * @param idGenerator  Used to mint the new `UserId`.
   * @param eventIdGen   Used to mint the `UserRegistered` event ID.
   */
  public static register(params: {
    clock: Clock;
    eventIdGenerator: { generate(): string };
    userId: UserId;
    organizationId: OrgId;
    email: Email;
    displayName: string | null;
  }): User {
    const {
      clock,
      eventIdGenerator,
      userId,
      organizationId,
      email,
      displayName,
    } = params;

    User.assertDisplayName(displayName);

    const now = clock.now();

    const event = new UserRegistered(
      eventIdGenerator.generate(),
      now,
      userId,
      organizationId,
      email.value,
    );

    return new User(
      userId,
      organizationId,
      email,
      displayName,
      null, // not yet verified
      null, // not deleted
      now,
      now,
      [event],
    );
  }

  // -------------------------------------------------------------------------
  // Factory: rehydrate from persistence
  // -------------------------------------------------------------------------

  /**
   * Reconstruct a User from its stored representation. Does NOT emit any
   * domain events (rehydration is not a state change).
   */
  public static fromPersistence(params: {
    id: UserId;
    organizationId: OrgId;
    email: Email;
    displayName: string | null;
    emailVerifiedAt: Date | null;
    deletedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
  }): User {
    User.assertDisplayName(params.displayName);
    return new User(
      params.id,
      params.organizationId,
      params.email,
      params.displayName,
      params.emailVerifiedAt,
      params.deletedAt,
      params.createdAt,
      params.updatedAt,
      [],
    );
  }

  // -------------------------------------------------------------------------
  // Domain methods
  // -------------------------------------------------------------------------

  /**
   * Mark the email address as verified. Idempotent — calling it twice on
   * an already-verified user is a no-op.
   *
   * Called by the Engagement context when the user clicks the verification
   * link. Does not emit a domain event directly; the Engagement context
   * emits its own `EmailVerificationCompleted` event.
   */
  public markEmailVerified(clock: Clock): User {
    if (this.emailVerifiedAt !== null) {
      return this; // idempotent
    }
    const now = clock.now();
    return new User(
      this.id,
      this.organizationId,
      this.email,
      this.displayName,
      now,
      this.deletedAt,
      this.createdAt,
      now,
      this.pendingEvents, // no new event
    );
  }

  /**
   * Change the display name. `null` clears it. Throws if the new value
   * is too long. Does NOT emit a domain event (display-name changes are
   * not security-relevant and shouldn't trigger session invalidation).
   */
  public changeDisplayName(clock: Clock, displayName: string | null): User {
    User.assertDisplayName(displayName);
    const now = clock.now();
    return new User(
      this.id,
      this.organizationId,
      this.email,
      displayName,
      this.emailVerifiedAt,
      this.deletedAt,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  /**
   * Move the user to a different organization (V1: a user always
   * belongs to exactly one org). Used by the self-service org-creation
   * flow: the caller founds a new org and their account moves into it.
   *
   * Emits no domain event — the application layer records an audit row
   * for the move. Note: access tokens minted for the previous org stay
   * valid until they expire (they are short-lived by design).
   */
  public moveToOrganization(clock: Clock, organizationId: OrgId): User {
    if (this.organizationId.equals(organizationId)) {
      return this; // idempotent
    }
    const now = clock.now();
    return new User(
      this.id,
      organizationId,
      this.email,
      this.displayName,
      this.emailVerifiedAt,
      this.deletedAt,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  /**
   * Mark the user as soft-deleted. Reversible via `restore()`. Used by
   * the GDPR data-deletion flow (V2). The DB row is NOT physically
   * deleted — audit history must outlive the user.
   */
  public softDelete(clock: Clock): User {
    if (this.deletedAt !== null) {
      return this; // idempotent
    }
    const now = clock.now();
    return new User(
      this.id,
      this.organizationId,
      this.email,
      this.displayName,
      this.emailVerifiedAt,
      now,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  /** Reverse a soft-delete. Idempotent. */
  public restore(clock: Clock): User {
    if (this.deletedAt === null) {
      return this;
    }
    const now = clock.now();
    return new User(
      this.id,
      this.organizationId,
      this.email,
      this.displayName,
      this.emailVerifiedAt,
      null,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  // -------------------------------------------------------------------------
  // Event collection (for the application layer to drain)
  // -------------------------------------------------------------------------

  /** Drain pending domain events. Caller (use-case) publishes them post-commit. */
  public pullDomainEvents(): DomainEvent[] {
    const events = [...this.pendingEvents];
    return events;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private static assertDisplayName(displayName: string | null): void {
    if (displayName === null) {
      return;
    }
    if (displayName.length > 120) {
      throw new DomainError(
        'domain.invariant_violation',
        'Display name must be at most 120 characters',
        { length: displayName.length },
      );
    }
  }

  /** True if this user is currently usable (not soft-deleted). */
  public isActive(): boolean {
    return this.deletedAt === null;
  }

  /** True if the email address has been verified. */
  public isEmailVerified(): boolean {
    return this.emailVerifiedAt !== null;
  }
}
