import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { DomainError } from '../../../shared/domain';
import { AppConfig } from '../../../config/configuration';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import { PUBLIC_KEY } from './public.decorator';
import { UserPrincipal } from '../../domain/value-objects/user-principal';

/**
 * Verify the request's Bearer JWT and attach a typed principal to
 * `req.user`.
 *
 * V1.5: replaces the `X-User-Id` placeholder header for all
 * authenticated REST endpoints. Clients now send
 * `Authorization: Bearer *** as real JWTs minted by
 * `POST /v1/oauth/token` (or the password-grant alias `/v1/auth/login`).
 *
 * Behavior:
 *
 *   1. If the route is marked `@Public()`, skip — `req.user` is left
 *      undefined and downstream code uses `@CurrentUser()` only if it
 *      explicitly requires auth.
 *   2. Extract `Authorization: Bearer *** header. Missing → 401
 *      `authentication.token.missing`.
 *   3. Verify the token via `JwtSignerService.verifyAccessToken`. The
 *      service validates signature, issuer, audience, and expiry.
 *      Any failure → 401 `authentication.token.invalid`.
 *   4. Build a `UserPrincipal` from the JWT claims:
 *      - `sub` → `userId`
 *      - `org` → `organizationSlug` (nullable)
 *      - `role` → `role` (nullable)
 *      - `scope` → `scopes` (split by space, OAuth2 standard)
 *      - `exp` → `expiresAt` (Date)
 *   5. Attach as `req.user`.
 *
 * The guard is deliberately stateless — it does NOT hit the database
 * to confirm the user still exists. JWT expiry + signing-key rotation
 * are the long-term freshness mechanisms; if you need database-backed
 * revocation, add a separate check here against a denylist.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private static readonly logger = new Logger(JwtAuthGuard.name);

  public constructor(
    private readonly reflector: Reflector,
    private readonly jwtSigner: JwtSignerService,
    private readonly config: ConfigService,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();
    const token = this.extractBearerToken(req);
    if (!token) {
      throw new DomainError(
        'authentication.token.missing',
        'Authorization: Bearer <token> header is required',
        { path: req.path },
      );
    }

    const issuer =
      this.config.getOrThrow<AppConfig['jwt']['issuer']>('jwt.issuer');
    const audience = this.config.getOrThrow<
      AppConfig['jwt']['audienceDefault']
    >('jwt.audienceDefault');

    let payload: Awaited<ReturnType<JwtSignerService['verifyAccessToken']>>;
    try {
      payload = await this.jwtSigner.verifyAccessToken({
        token,
        issuer,
        audience,
      });
    } catch (err) {
      // V1.5 (audit L-5): log the underlying jose error server-side
      // but DO NOT include it in the DomainError metadata — the
      // response body echoes `meta.reason` and we don't want to leak
      // jose internals ("JWT expired", "issuer mismatch", etc.) to
      // an attacker probing the token surface.
      JwtAuthGuard.logger.warn(`JWT verification failed: ${String(err)}`);
      throw new DomainError(
        'authorization.token.invalid',
        'JWT verification failed',
      );
    }

    const principal = this.toPrincipal(payload);
    (req as Request & { user: UserPrincipal }).user = principal;
    return true;
  }

  private extractBearerToken(req: Request): string | null {
    const header = req.headers['authorization'];
    if (typeof header !== 'string') {
      return null;
    }
    const m = header.match(/^Bearer\s+(.+)$/i);
    if (!m) {
      return null;
    }
    return m[1].trim();
  }

  private toPrincipal(payload: Record<string, unknown>): UserPrincipal {
    const sub = typeof payload.sub === 'string' ? payload.sub : '';
    const org = typeof payload.org === 'string' ? payload.org : null;
    const role = typeof payload.role === 'string' ? payload.role : null;
    const rawScopes = typeof payload.scope === 'string' ? payload.scope : '';
    const exp = typeof payload.exp === 'number' ? payload.exp : 0;
    return {
      userId: sub,
      organizationSlug: org,
      role,
      scopes: rawScopes.split(/\s+/).filter((s) => s.length > 0),
      expiresAt: new Date(exp * 1000),
    };
  }
}
