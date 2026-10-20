import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Guard for `POST /v1/identity/mfa/verify` (audit 2026-10-19 fix C1).
 *
 * The endpoint must accept EITHER:
 *
 *   * a normal access JWT with scope `auth:write` (legacy callers that
 *     already hold a full token), OR
 *   * the `mfa:verify`-scoped pending token issued by login when MFA
 *     is still outstanding (the C1 flow — the caller has completed
 *     the first factor but owns no full-access token yet).
 *
 * The standard `ScopesGuard` requires `auth:write` and would reject
 * pending tokens, so this guard delegates JWT verification to
 * `JwtAuthGuard` and then applies the scope alternation itself.
 */
@Injectable()
export class MfaVerifyGuard implements CanActivate {
  /** Scopes that admit a caller to the MFA-verify endpoint. */
  private static readonly ACCEPTED_SCOPES = ['auth:write', 'mfa:verify'];

  public constructor(private readonly jwtAuthGuard: JwtAuthGuard) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    // Verifies the signature/issuer/audience/expiry and attaches the
    // principal to req.user. Throws 401 on any token problem.
    await this.jwtAuthGuard.canActivate(context);

    const req = context.switchToHttp().getRequest<Request>();
    const principal = (req as Request & { user?: UserPrincipal }).user;
    if (!principal) {
      throw new UnauthorizedException('Authentication required');
    }
    const admitted = principal.scopes.some((s) =>
      MfaVerifyGuard.ACCEPTED_SCOPES.includes(s),
    );
    if (!admitted) {
      throw new UnauthorizedException(
        'Missing required scope(s): auth:write or mfa:verify',
      );
    }
    return true;
  }
}
