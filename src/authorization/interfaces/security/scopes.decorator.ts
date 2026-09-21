import { SetMetadata } from '@nestjs/common';

/**
 * Require that the caller's JWT contains ALL of the listed scopes.
 *
 * Used together with `ScopesGuard` (which runs AFTER `JwtAuthGuard`):
 *
 *   @UseGuards(JwtAuthGuard, ScopesGuard)
 *   @Scopes('auth:write')
 *   public async changePassword(...) { ... }
 *
 * Scope rules:
 *   * `auth:read` — read-only access to the caller's own data
 *     (sessions, profile, audit log, email verification request)
 *   * `auth:write` — modify the caller's own account
 *     (change password, enable/disable MFA, etc.)
 *   * `org:admin` — admin operations on the caller's org
 *   * (admin:* — out of scope; admin uses a separate listener)
 */
export const SCOPES_KEY = 'cerberus:required-scopes';
export const Scopes = (...scopes: string[]): MethodDecorator =>
  SetMetadata(SCOPES_KEY, scopes);
