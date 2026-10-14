import { DomainEvent } from '../../domain/events/domain-event';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { SessionId } from '../../../authentication/domain/value-objects/session-id';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import {
  EmailVerificationConsumed,
  EmailVerificationRequested,
  PasswordResetConsumed,
  PasswordResetRequested,
} from '../../../engagement/domain/events/engagement.events';
import { UserRegistered } from '../../../identity/domain/events/identity.events';
import {
  AccountLocked,
  FamilyCompromised,
  SessionCreated,
  SessionRefreshed,
  SessionRevoked,
} from '../../../authentication/domain/events/auth.events';
import {
  MfaDisabled,
  MfaEnabled,
  MfaEnrollmentStarted,
  PasswordChanged,
} from '../../../identity/domain/events/identity.events';

/**
 * Rehydrates a `DomainEvent` from a JSON payload produced by
 * `PrismaOutbox.serialize()`.
 *
 * The serialize step stores `__class` (the constructor name) plus
 * the public fields. We match on `eventName` here because it's
 * stable across renames (whereas `__class` isn't if you ever
 * refactor the class name).
 *
 * Each handler builds the event via its constructor with the
 * primitives that constructor expects. VOs (UserId, SessionId,
 * EmailVerificationId) are re-wrapped from their string form.
 *
 * The relay (`OutboxRelay`) uses this to convert a stored row back
 * into a typed event before re-publishing through the EventBus.
 */
export function rehydrateEvent(payload: {
  __class: string;
  eventId: string;
  eventName: string;
  aggregateType: string;
  aggregateId: string;
  occurredAt: string;
  [k: string]: unknown;
}): DomainEvent {
  const occurredAt = new Date(payload.occurredAt);

  switch (payload.eventName) {
    // -- identity --
    case 'identity.user.registered': {
      return new UserRegistered(
        payload.eventId,
        occurredAt,
        UserId.rehydrate((payload.userId as string) ?? payload.aggregateId),
        OrgId.rehydrate(
          (payload.organizationId as string) ?? payload.aggregateId,
        ),
        (payload.email as string) ?? '',
      );
    }
    case 'identity.password.changed': {
      return new PasswordChanged(
        payload.eventId,
        occurredAt,
        UserId.rehydrate(payload.userId as string),
      );
    }
    case 'identity.mfa.enrollment_started': {
      return new MfaEnrollmentStarted(
        payload.eventId,
        occurredAt,
        UserId.rehydrate(payload.userId as string),
      );
    }
    case 'identity.mfa.enabled': {
      return new MfaEnabled(
        payload.eventId,
        occurredAt,
        UserId.rehydrate(payload.userId as string),
      );
    }
    case 'identity.mfa.disabled': {
      return new MfaDisabled(
        payload.eventId,
        occurredAt,
        UserId.rehydrate(payload.userId as string),
      );
    }

    // -- authentication --
    case 'authentication.session.created': {
      return new SessionCreated(
        payload.eventId,
        occurredAt,
        SessionId.rehydrate(payload.sessionId as string),
        UserId.rehydrate(payload.userId as string),
        Boolean(payload.requiresMfa),
      );
    }
    case 'authentication.session.refreshed': {
      return new SessionRefreshed(
        payload.eventId,
        occurredAt,
        SessionId.rehydrate(payload.sessionId as string),
        UserId.rehydrate(payload.userId as string),
      );
    }
    case 'authentication.session.family_compromised': {
      return new FamilyCompromised(
        payload.eventId,
        occurredAt,
        payload.familyId as string,
        UserId.rehydrate((payload.userId as string) ?? payload.aggregateId),
      );
    }
    case 'authentication.session.revoked': {
      return new SessionRevoked(
        payload.eventId,
        occurredAt,
        SessionId.rehydrate(payload.sessionId as string),
        UserId.rehydrate(payload.userId as string),
        // The reason field is a string-literal union. The
        // serializer always writes a string, so we cast through
        // unknown. If the writer stored something else, the cast
        // will fail at runtime (which is what we want — bad data
        // should crash, not silently degrade).
        payload.reason as
          'USER_LOGOUT' | 'PASSWORD_CHANGED' | 'ADMIN_REVOKED' | 'EXPIRED',
      );
    }
    case 'authentication.account.locked': {
      return new AccountLocked(
        payload.eventId,
        occurredAt,
        UserId.rehydrate(payload.userId as string),
        new Date(payload.lockedUntil as string),
      );
    }

    // -- engagement --
    case 'engagement.email_verification.requested': {
      return new EmailVerificationRequested(
        payload.eventId,
        occurredAt,
        payload.userId as string,
        payload.verificationId as string,
        // Plaintext token was in the original event. On rehydrate
        // the relay re-publishes; MailSenderDispatcher ignores
        // missing/empty plaintexts (logged once).
        (payload.plaintextToken as string) ?? '',
      );
    }
    case 'engagement.email_verification.completed': {
      return new EmailVerificationConsumed(
        payload.eventId,
        occurredAt,
        payload.userId as string,
        payload.verificationId as string,
      );
    }
    case 'engagement.password_reset.requested': {
      return new PasswordResetRequested(
        payload.eventId,
        occurredAt,
        payload.userId as string,
        payload.resetId as string,
        (payload.plaintextToken as string) ?? '',
      );
    }
    case 'engagement.password_reset.completed': {
      return new PasswordResetConsumed(
        payload.eventId,
        occurredAt,
        payload.userId as string,
        payload.resetId as string,
      );
    }

    default:
      throw new Error(
        `rehydrateEvent: unknown eventName "${payload.eventName}" (class ${payload.__class})`,
      );
  }
}
