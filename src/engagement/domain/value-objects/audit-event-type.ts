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
  'admin.organization.created',
  // Apps (V1.5+)
  'apps.app.registered',
  'apps.app.key_rotated',
  'apps.app.revoked',
  // V1.6 client_credentials grant: emitted when Cerberus mints a
  // JWT for an App via the OAuth2 client_credentials grant. Mirrors
  // `authorization.token.minted` for user-bound tokens. userId on
  // the audit row is the App UUID (free-form text column — apps
  // don't have a User UUID).
  'apps.token.issued',
  // V1.7 audit fix #10: client_credentials grant failure. Logged
  // for security audit trails so operators can replay-attack
  // detection. Does NOT include the plaintext client_secret.
  'app.auth.failed',
  // Authorization
  'authorization.token.minted',
  'authorization.token.revoked',
  // 2026-10-19 audit fixes (B1): refresh-token reuse detection now emits
  // an audit trail, MFA-pending login issuances are throttled per email,
  // and refresh attempts against an MFA-unverified session are recorded.
  'authentication.refresh.reuse_detected',
  'authentication.refresh.family_revoked',
  'authentication.login.throttled',
  'authentication.mfa.required',
  // 2026-10-19 audit fixes (identity/engagement workstream):
  // H-5b — both MFA-verify outcomes; MEDIUM — password-reset rotation
  // audit + opaque registration duplicates + post-verification
  // email-domain org joins.
  'identity.mfa.verified',
  'identity.mfa.verification_failed',
  'identity.password.reset',
  'identity.registration.duplicate',
  'identity.organization.joined_by_domain',
  // Self-service org creation: emitted when an authenticated user
  // founds their own org via POST /v1/identity/orgs (or the GraphQL
  // `createOwnOrganization` mutation). Distinct from the operator
  // `admin.organization.created` above.
  'identity.organization.created_by_user',
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
