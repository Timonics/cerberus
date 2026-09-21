import { DomainEvent } from '../../../shared/domain/events/domain-event';

/**
 * Emitted when an email-verification token is REQUESTED. The token's
 * plaintext IS in the event payload — the mail sender needs it to
 * render the verification URL, and the plaintext is never persisted
 * (only the hash is stored in `email_verifications.token`).
 *
 * SECURITY NOTE: only trusted in-process subscribers should consume
 * this event. In V1 the only subscriber is the mail sender; if you
 * add an external subscriber (webhook, message queue, etc.) in the
 * future, scrub the plaintext first.
 *
 * Consumers:
 *   * Mail sender adapter — renders the verification email with the
 *     token URL.
 *   * Audit log — appends an entry (does not log the plaintext).
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
    public readonly plaintextToken: string,
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
    public readonly plaintextToken: string,
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
