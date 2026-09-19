import {
  BadRequestException,
  ExecutionContext,
  createParamDecorator,
} from '@nestjs/common';
import { Request } from 'express';

/**
 * `@UserIdHeader()` — extracts the `X-User-Id` header value (Phase 11
 * placeholder auth) and throws a clean 400 BadRequestException if it's
 * missing.
 *
 * V1: the auth context is still wired via the `X-User-Id` header on
 * most protected endpoints (login flow returns the userId, the client
 * passes it back). This decorator centralises the validation that
 * those endpoints need.
 *
 * V1.5: replace with `JwtAuthGuard` + `@CurrentUser()` (Authorization
 * BC). The decorator should be deleted at the same time the controller
 * methods lose their `X-User-Id` reads.
 */
export const UserIdHeader = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const raw = req.headers['x-user-id'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const trimmed = typeof value === 'string' ? value.trim() : '';
    if (!trimmed) {
      throw new BadRequestException(
        'Missing or empty X-User-Id header (Phase 11 placeholder auth)',
      );
    }
    return trimmed;
  },
);
