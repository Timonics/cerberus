import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { GraphqlContext } from '../graphql-context';

/**
 * GraphQL auth guard.
 *
 * Decorate resolver methods with `@AuthGuard()` to require a valid
 * bearer token. Decorate with `@AuthGuard({ requireOrgAdmin: true })`
 * to additionally require the `org:admin` scope (OWNER / ADMIN role).
 *
 * Mirrors `JwtAuthGuard` from the Authorization BC. We use a guard
 * rather than a context-mutation middleware because resolvers opt in
 * explicitly — that way an unauthenticated query like `health` works
 * without auth.
 *
 * Error mapping:
 *   * Missing / invalid token → `UnauthorizedException` → GraphQL
 *     error code `UNAUTHENTICATED`.
 *   * Missing required scope → `ForbiddenException` → `FORBIDDEN`.
 */
@Injectable()
export class GraphqlAuthGuard implements CanActivate {
  public constructor(private readonly reflector: Reflector) {}

  public canActivate(context: ExecutionContext): boolean {
    const options = this.reflector.get<{
      requireOrgAdmin?: boolean;
    }>('graphql-auth-options', context.getHandler());
    const ctx =
      GqlExecutionContext.create(context).getContext<GraphqlContext>();
    const user = ctx.currentUser;
    if (!user) {
      throw new UnauthorizedException('Authentication required');
    }
    if (options?.requireOrgAdmin) {
      // V1.7 (audit H-3): `requireOrgAdmin` is a USER-principal
      // check. App-bound tokens are already rejected before the
      // context is populated; this is defense in depth so a future
      // caller that opts app tokens into the context can never
      // satisfy an org-admin check with one.
      if (user.typ === 'app') {
        throw new ForbiddenException('User principal required');
      }
      if (!user.scopes.includes('org:admin')) {
        throw new ForbiddenException('org:admin scope required');
      }
    }
    return true;
  }
}
