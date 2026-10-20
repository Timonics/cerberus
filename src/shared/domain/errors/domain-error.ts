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
  // 2026-10-19 audit fix C1: refresh attempted against a session whose
  // MFA verification is still pending. Mapped to 401 by
  // DomainErrorFilter (same class as invalid_credentials — the caller
  // holds a token but has not completed the second factor).
  | 'authentication.mfa.required'
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
  // Audit 2026-10-19 (admin LOW): revoke would remove the last ACTIVE
  // admin key. Mapped to 409 by DomainErrorFilter.
  | 'admin.key.last_active'
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
  // V1.7: bad client_id or client_secret on the client_credentials
  // grant. Mapped to 401 + WWW-Authenticate: Basic by
  // DomainErrorFilter. Kept distinct from `app.auth.invalid`
  // (used by the admin-side key guard) so the audit + observability
  // layer can tell apart "API key was rejected by the guard" from
  // "OAuth2 client_credentials grant was rejected at the token
  // endpoint" without parsing the message.
  | 'app.auth.failed'
  // V1.7 (audit H-3 + app-credentials oracle): unknown app / revoked
  // app / missing / revoked / expired key / wrong secret all map to
  // this ONE code from VerifyAppApiKeyUseCase — the distinct codes
  // above remain for read-side paths that already know the app
  // exists. Mapped to 401 by DomainErrorFilter (credential failure,
  // same class as invalid_credentials); HTTP callers that need the
  // uniform body rethrow it themselves.
  | 'app.credentials.invalid'
  // V1.7 (audit H-3): registration requested a scope outside the
  // server-side app-scope registry. Mapped to 400 by
  // DomainErrorFilter (`.invalid` suffix).
  | 'app.scope.invalid'
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
