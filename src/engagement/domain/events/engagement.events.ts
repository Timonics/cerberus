import { DomainEvent } from '../../../shared/domain/events/domain-event';

/**
 * Emitted when an email-verification token is REQUESTED. The token's
 * plaintext is NOT in the event payload (security: the event travels
 * across the bus to subscribers and we don't want the plaintext leaking).
 *
 * Consumers:
 *   * Mail sender adapter — renders the verification email with the
 *     token URL.
 *   * Audit log — appends an entry.
 */
export class EmailVerificationRequested implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'EmailVerification';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'engagement.email_verification.requested';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: string,
    public readonly verificationId: string,
  ) {
    this.eventId = eventId;
    this.aggregateId = verificationId;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when the verification token is CONSUMED (user clicked the
 * link in the email and the use-case confirmed it).
 *
 * Consumers:
 *   * Audit log.
 */
export class EmailVerificationConsumed implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'EmailVerification';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'engagement.email_verification.completed';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: string,
    public readonly verificationId: string,
  ) {
    this.eventId = eventId;
    this.aggregateId = verificationId;
    this.occurredAt = occurredAt;
  }
}

export class PasswordResetRequested implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'PasswordReset';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'engagement.password_reset.requested';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: string,
    public readonly resetId: string,
  ) {
    this.eventId = eventId;
    this.aggregateId = resetId;
    this.occurredAt = occurredAt;
  }
}

export class PasswordResetConsumed implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'PasswordReset';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'engagement.password_reset.completed';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: string,
    public readonly resetId: string,
  ) {
    this.eventId = eventId;
    this.aggregateId = resetId;
    this.occurredAt = occurredAt;
  }
}
