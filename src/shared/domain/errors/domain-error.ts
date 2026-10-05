/**
 * Domain error base class.
 *
 * Domain errors are *expected* failure modes that a use-case can decide how to
 * handle (return a friendly HTTP 4xx, retry, escalate). They are *not*
 * exceptional — do not throw them from infrastructural code (e.g. a database
 * timeout is a system error, not a domain error).
 *
 * Every domain error carries a stable, machine-readable `code` so that HTTP
 * adapters and SDKs can map it to a typed response without parsing strings.
 */
export type DomainErrorCode =
  // Identity
  | 'identity.email.invalid'
  | 'identity.email.taken'
  | 'identity.password.too_weak'
  | 'identity.password.reused'
  | 'identity.user.not_found'
  | 'identity.credential.locked'
  | 'identity.mfa.already_enabled'
  | 'identity.mfa.not_enabled'
  | 'identity.mfa.code_invalid'
  | 'identity.mfa.recovery_code_invalid'
  | 'identity.organization.name_required'
  | 'identity.organization.name_too_long'
  | 'identity.organization.description_too_long'
  | 'identity.organization.slug_taken'
  | 'identity.organization.not_found'
  // Authentication
  | 'authentication.invalid_credentials'
  | 'authentication.account_locked'
  | 'authentication.session.not_found'
  | 'authentication.session.expired'
  | 'authentication.session.revoked'
  | 'authentication.refresh_token_reused'
  | 'authentication.rate_limited'
  | 'authentication.token.missing'
  | 'authentication.app_membership_required'
  // Authorization
  | 'authorization.role.not_found'
  | 'authorization.token.invalid'
  | 'authorization.token.expired'
  // Engagement
  | 'engagement.email_verification.invalid_token'
  | 'engagement.email_verification.expired'
  | 'engagement.email_verification.already_consumed'
  | 'engagement.password_reset.invalid_token'
  | 'engagement.password_reset.expired'
  // Administration
  | 'admin.api_key.not_found'
  | 'admin.api_key.revoked'
  | 'admin.api_key.expired'
  | 'admin.api_key.ttl_non_positive'
  | 'admin.role.unknown'
  | 'admin.ip_not_allowed'
  | 'admin.auth.missing'
  | 'admin.auth.invalid'
  | 'admin.forbidden'
  | 'admin.audit.search.too_broad'
  | 'admin.audit.search.invalid_int'
  | 'admin.audit.search.out_of_range'
  | 'admin.audit.search.invalid_range'
  | 'admin.user.mfa_not_enabled'
  // Apps (per-app integration credentials)
  | 'app.not_found'
  | 'app.revoked'
  | 'app.api_key.not_found'
  | 'app.api_key.revoked'
  | 'app.api_key.expired'
  | 'app.api_key.ttl_non_positive'
  | 'app.api_key.invalid'
  | 'app.organization.not_found'
  | 'app.auth.missing'
  | 'app.auth.invalid'
  // Generic
  | 'domain.invariant_violation'
  | 'domain.illegal_state';

export class DomainError extends Error {
  /** Stable, machine-readable error code. UI/SDKs should branch on this. */
  public readonly code: DomainErrorCode;

  /**
   * Optional structured detail that callers may attach (e.g. which constraint
   * failed, which field). Never include PII or secrets — this is logged.
   */
  public readonly detail?: Readonly<Record<string, unknown>>;

  public constructor(
    code: DomainErrorCode,
    message: string,
    detail?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'DomainError';
    this.code = code;
    this.detail = detail;

    // Restore prototype chain after super() — required when targeting ES5/ES2015
    // transpilation. Safe under ES2023 too.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Render to a JSON-safe shape for HTTP responses. PII fields (email, IPs)
   * are intentionally NOT included here — those belong in audit logs, not in
   * the public error payload.
   */
  public toJSON(): { code: DomainErrorCode; message: string } {
    return { code: this.code, message: this.message };
  }
}
