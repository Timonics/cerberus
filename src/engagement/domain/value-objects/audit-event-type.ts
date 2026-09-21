import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Audit-event types.
 *
 * Each event has a stable string code (the value below). The string is
 * used as the `eventType` column in the audit_log table and as the
 * `audit_log.event_type` field in any structured log output.
 *
 * V1 ships the minimum set needed by the Identity + Authentication +
 * Engagement contexts. Phase 15 (Administration) adds admin events.
 */
export const AUDIT_EVENT_TYPES = [
  // Identity
  'identity.user.registered',
  'identity.email.verified',
  'identity.password.changed',
  'identity.mfa.enabled',
  'identity.mfa.disabled',
  'identity.account.locked',
  // Authentication
  'authentication.login.succeeded',
  'authentication.login.failed',
  'authentication.session.revoked',
  'authentication.account.locked',
  // Engagement
  'engagement.email_verification.requested',
  'engagement.email_verification.completed',
  'engagement.password_reset.requested',
  'engagement.password_reset.completed',
  // Administration (V1.5+)
  'admin.api_key.issued',
  'admin.api_key.revoked',
  'admin.user.mfa_disabled',
  'admin.audit.searched',
  // Apps (V1.5+)
  'apps.app.registered',
  'apps.app.key_rotated',
  'apps.app.revoked',
  // Authorization
  'authorization.token.minted',
  'authorization.token.revoked',
] as const;

export type AuditEventTypeLiteral = (typeof AUDIT_EVENT_TYPES)[number];

const EVENT_TYPE_SET = new Set<string>(AUDIT_EVENT_TYPES);

/**
 * Validated audit-event-type value object.
 */
export class AuditEventType {
  public readonly value: AuditEventTypeLiteral;

  private constructor(value: AuditEventTypeLiteral) {
    this.value = value;
  }

  public static create(raw: string): AuditEventType {
    if (!EVENT_TYPE_SET.has(raw)) {
      throw new DomainError(
        'domain.invariant_violation',
        `Unknown audit event type: ${raw}`,
      );
    }
    return new AuditEventType(raw as AuditEventTypeLiteral);
  }

  public static rehydrate(value: string): AuditEventType {
    return AuditEventType.create(value);
  }

  public toString(): string {
    return this.value;
  }

  public equals(other: AuditEventType): boolean {
    return this.value === other.value;
  }
}
