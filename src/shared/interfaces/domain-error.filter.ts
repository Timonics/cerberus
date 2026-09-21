import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { DomainError } from '../domain/errors/domain-error';

/**
 * Global filter that maps `DomainError` → HTTP response.
 *
 * Status code is derived from the error code prefix:
 *
 *   * `identity.user.not_found`, `identity.mfa.not_enabled` → 404
 *   * `identity.email.invalid`, `identity.password.too_weak`,
 *     `identity.password.reused` → 422 (unprocessable)
 *   * `identity.email.taken`, `identity.credential.locked` → 409 (conflict)
 *   * `identity.mfa.code_invalid`, `identity.mfa.recovery_code_invalid`,
 *     `authentication.invalid_credentials` → 401
 *   * `authorization.role.not_found`, `authorization.token.invalid` → 401
 *   * `authorization.token.expired` → 401
 *   * `engagement.*` → 400 (bad request)
 *   * `domain.invariant_violation`, `domain.illegal_state` → 409
 *
 * Anything not matched falls through to the default Nest error handler
 * (which returns 500). This means truly unexpected errors are loud, while
 * expected-but-bad-request outcomes are returned cleanly.
 */
@Catch(DomainError)
export class DomainErrorFilter implements ExceptionFilter {
  private readonly logger = new Logger(DomainErrorFilter.name);

  public catch(exception: DomainError, host: ArgumentsHost): void {
    // Skip if this isn't an HTTP context (e.g. GraphQL routed here too).
    // DomainErrorFilter is registered as a REST exception filter; for
    // GraphQL we have `GraphqlDomainErrorFilter`.
    if (host.getType<string>() !== 'http') {
      throw exception;
    }
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = DomainErrorFilter.statusFor(exception);

    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      // Truly unexpected — log with stack, return generic 500.
      this.logger.error(
        `Unhandled domain error [${exception.code}] at ${request.method} ${request.url}: ${exception.message}`,
        exception.stack,
      );
      response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        code: 'internal.error',
        message: 'Internal server error',
      });
      return;
    }

    // Expected — log at debug, return clean JSON.
    this.logger.debug(
      `[${status}] ${request.method} ${request.url} -> ${exception.code}: ${exception.message}`,
    );
    response.status(status).json(exception.toJSON());
  }

  private static statusFor(error: DomainError): HttpStatus {
    switch (error.code) {
      // 400 — bad request
      case 'engagement.email_verification.invalid_token':
      case 'engagement.email_verification.expired':
      case 'engagement.email_verification.already_consumed':
      case 'engagement.password_reset.invalid_token':
      case 'engagement.password_reset.expired':
        return HttpStatus.BAD_REQUEST;

      // 401 — unauthenticated / bad credentials
      case 'authentication.invalid_credentials':
      case 'authentication.account_locked':
      case 'authentication.session.not_found':
      case 'authentication.session.expired':
      case 'authentication.session.revoked':
      case 'authentication.refresh_token_reused':
      case 'authorization.token.invalid':
      case 'authorization.token.expired':
      case 'authorization.role.not_found':
      case 'identity.mfa.code_invalid':
      case 'identity.mfa.recovery_code_invalid':
      case 'admin.auth.missing':
      case 'admin.auth.invalid':
      case 'admin.api_key.revoked':
      case 'admin.api_key.expired':
      case 'admin.api_key.not_found':
      case 'app.auth.missing':
      case 'app.auth.invalid':
      case 'app.api_key.revoked':
      case 'app.api_key.expired':
      case 'app.api_key.not_found':
      case 'app.api_key.invalid':
      case 'authentication.token.missing':
        return HttpStatus.UNAUTHORIZED;

      case 'admin.ip_not_allowed':
      case 'app.revoked':
      case 'authentication.app_membership_required':
        return HttpStatus.FORBIDDEN;

      case 'admin.audit.search.too_broad':
      case 'admin.audit.search.invalid_int':
      case 'admin.audit.search.out_of_range':
      case 'admin.audit.search.invalid_range':
        return HttpStatus.BAD_REQUEST;

      // 404 — not found
      case 'identity.user.not_found':
      case 'identity.mfa.not_enabled':
      case 'admin.user.mfa_not_enabled':
      case 'app.not_found':
      case 'app.organization.not_found':
        return HttpStatus.NOT_FOUND;

      // 409 — conflict
      case 'identity.email.taken':
      case 'identity.credential.locked':
      case 'identity.mfa.already_enabled':
      case 'domain.invariant_violation':
      case 'domain.illegal_state':
        return HttpStatus.CONFLICT;

      // 422 — unprocessable (semantic validation failure)
      case 'identity.email.invalid':
      case 'identity.password.too_weak':
      case 'identity.password.reused':
        return HttpStatus.UNPROCESSABLE_ENTITY;

      // 429 — rate limited
      case 'authentication.rate_limited':
        return HttpStatus.TOO_MANY_REQUESTS;

      default:
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
  }
}

/**
 * Re-export the catch decorator's symbol so app.module can register the
 * filter globally via `APP_FILTER`.
 */

const _ensureHttpExceptionImportKept: HttpException =
  null as unknown as HttpException;
void _ensureHttpExceptionImportKept;
