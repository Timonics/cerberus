import { SetMetadata } from '@nestjs/common';

/**
 * Mark a route as public — bypasses JwtAuthGuard.
 *
 * Used for endpoints that should not require any authentication:
 *   * `GET /health` — load balancer probes
 *   * `POST /v1/auth/login` — get a token
 *   * `POST /v1/auth/refresh` — exchange a refresh token
 *   * `POST /v1/identity/register` — create an account
 *   * `POST /v1/engagement/email-verification/confirm` — public confirm
 *   * `POST /v1/engagement/password-reset/confirm` — public confirm
 *   * `GET /.well-known/jwks.json` — public key set
 *
 * V1.5 replaces the `X-User-Id` header placeholder auth, so any
 * endpoint that didn't have `@UserIdHeader()` should now use this.
 */
export const PUBLIC_KEY = 'cerberus:public-route';
export const Public = (): MethodDecorator & ClassDecorator =>
  SetMetadata(PUBLIC_KEY, true);
