import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { SessionId } from '../value-objects/session-id';
import { UserId } from '../../../identity/domain/value-objects/user-id';

/**
 * Emitted on successful first-factor login (password correct, account
 * not locked). The Authorization context listens for this and issues
 * the JWT. The Engagement context listens for "login from new device"
 * notifications (V1.5).
 */
export class SessionCreated implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'Session';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'authentication.session.created';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly sessionId: SessionId,
    public readonly userId: UserId,
    public readonly requiresMfa: boolean,
  ) {
    this.eventId = eventId;
    this.aggregateId = sessionId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when a refresh token is presented. The Authorization context
 * re-issues a fresh JWT; nothing else listens.
 */
export class SessionRefreshed implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'Session';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'authentication.session.refreshed';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly sessionId: SessionId,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = sessionId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when a refresh token from a family is presented twice (the
 * first presentation already rotated it). Used by alerting / security
 * dashboards; the Authentication context also revokes the entire
 * family synchronously before emitting.
 */
export class FamilyCompromised implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'SessionFamily';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'authentication.session.family_compromised';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly familyId: string,
    public readonly userId: UserId,
  ) {
    this.eventId = eventId;
    this.aggregateId = familyId;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted on a single session revoke (logout, password change, etc.).
 * The Authorization context drops any cached state for this session ID.
 */
export class SessionRevoked implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'Session';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'authentication.session.revoked';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly sessionId: SessionId,
    public readonly userId: UserId,
    public readonly reason:
      'USER_LOGOUT' | 'PASSWORD_CHANGED' | 'ADMIN_REVOKED' | 'EXPIRED',
  ) {
    this.eventId = eventId;
    this.aggregateId = sessionId.value;
    this.occurredAt = occurredAt;
  }
}

/**
 * Emitted when an account is locked due to brute-force attempts.
 * Used by the Engagement context to send a "your account was temporarily
 * locked" email (V1.5).
 */
export class AccountLocked implements DomainEvent {
  public readonly eventId: string;
  public readonly aggregateType = 'Credential';
  public readonly aggregateId: string;
  public readonly occurredAt: Date;
  public readonly eventName = 'authentication.account_locked';

  public constructor(
    eventId: string,
    occurredAt: Date,
    public readonly userId: UserId,
    public readonly lockedUntil: Date,
  ) {
    this.eventId = eventId;
    this.aggregateId = userId.value;
    this.occurredAt = occurredAt;
  }
}
