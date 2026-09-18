import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { OrgId } from '../value-objects/org-id';
import { UserId } from '../value-objects/user-id';

/**
 * Emitted when a new user is registered (and the corresponding organization
 * is created on their behalf, in V1 single-org-per-user).
 *
 * Consumers:
 *   * Authorization context — grants a default `MEMBER` role for the user.
 *   * Engagement context — creates an EmailVerification token and sends a
 *     welcome email.
 *   * Audit log — records the registration.
 */
export class UserRegistered implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'User';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'identity.user.registered';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
    public readonly organizationId: OrgId,
    public readonly email: string,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when the user changes their password. Consumers:
 *   * Authentication context — revokes all live sessions for this user.
 *   * Audit log.
 */
export class PasswordChanged implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'User';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'identity.password.changed';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when a user begins the MFA enrollment flow. The secret has been
 * generated and stored; the user is expected to confirm by providing a
 * valid TOTP code.
 */
export class MfaEnrollmentStarted implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'User';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'identity.mfa.enrollment_started';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when the user confirms MFA enrollment with a valid first TOTP
 * code. At this point MFA is *active* for the user.
 */
export class MfaEnabled implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'User';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'identity.mfa.enabled';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when the user disables MFA entirely (with a fresh TOTP code as
 * confirmation). Consumers revoke any cached second-factor state.
 */
export class MfaDisabled implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'User';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'identity.mfa.disabled';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}
