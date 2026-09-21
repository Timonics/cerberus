import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { UserPrincipal } from '../../domain/value-objects/user-principal';

/**
 * Extract the authenticated principal from the request.
 *
 * `JwtAuthGuard` populates `req.user` after verifying the bearer
 * token. This decorator just plucks it out. If `JwtAuthGuard` did
 * NOT run on the route (e.g. the route is `@Public()`), `req.user`
 * is undefined and we throw 401 — that means the route is not
 * supposed to receive a principal but the developer forgot.
 *
 * Usage:
 *
 *   @Get('me')
 *   @UseGuards(JwtAuthGuard)
 *   public async me(@CurrentUser() principal: UserPrincipal) {
 *     return this.getUser.execute({ userId: principal.userId });
 *   }
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): UserPrincipal => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const principal = (req as Request & { user?: UserPrincipal }).user;
    if (!principal) {
      throw new UnauthorizedException(
        'No authenticated principal — did you forget @UseGuards(JwtAuthGuard)?',
      );
    }
    return principal;
  },
);
