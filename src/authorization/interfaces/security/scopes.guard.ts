import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { SCOPES_KEY } from './scopes.decorator';
import {
  hasAllScopes,
  UserPrincipal,
} from '../../domain/value-objects/user-principal';

/**
 * Enforce that the caller's JWT carries the required scopes.
 *
 * MUST run AFTER `JwtAuthGuard` so `req.user` is populated. If
 * `JwtAuthGuard` didn't run (e.g. the route is `@Public()`), this
 * guard has nothing to check — it returns false.
 *
 * V1.7 (audit H-3): app-bound tokens never reach this guard —
 * `JwtAuthGuard` rejects `typ: 'app'` tokens before attaching
 * `req.user`, so the principal here is always user-bound.
 *
 * Throws `UnauthorizedException` on insufficient scope. We use
 * `UnauthorizedException` (401) rather than `ForbiddenException` (403)
 * because OAuth2 RFC 6750 specifies 401 + `WWW-Authenticate: Bearer
 * error="insufficient_scope"` for scope failures.
 */
@Injectable()
export class ScopesGuard implements CanActivate {
  public constructor(private readonly reflector: Reflector) {}

  public canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();
    const principal = (req as Request & { user?: UserPrincipal }).user;
    if (!principal) {
      throw new UnauthorizedException(
        'ScopesGuard requires JwtAuthGuard to run first',
      );
    }
    if (!hasAllScopes(principal, required)) {
      throw new UnauthorizedException(
        `Missing required scope(s): ${required.join(', ')}`,
      );
    }
    return true;
  }
}
