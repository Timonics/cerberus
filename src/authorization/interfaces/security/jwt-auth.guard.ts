import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { VerifyAccessTokenUseCase } from '../../application/use-cases/verify-access-token.use-case';

declare module 'express' {
  /** Augment Express's `Request` with our verified claims. */
  interface Request {
    /**
     * Set by `JwtAuthGuard` after a successful verification. Routes
     * downstream of the guard can rely on this being present.
     */
    user?: {
      sub: string;
      org: string | null;
      role: string | null;
      scopes: ReadonlyArray<string>;
      jti: string;
    };
  }
}

/**
 * Extract a Bearer token from the Authorization header, verify it, and
 * attach the decoded claims to `request.user`.
 *
 * V1: any successful verification authorizes the request. Scope-based
 * authorization is a separate concern (`ScopesGuard`) — this guard
 * only checks "is the token valid?". The scopes check is layered on
 * top via `@Scopes('auth:write')` decorator + ScopesGuard (V1.5).
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  public constructor(
    private readonly verifyAccessTokenUc: VerifyAccessTokenUseCase,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const header = request.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return false;
    }
    const token = header.substring('Bearer '.length).trim();
    if (!token) {
      return false;
    }

    try {
      const claims = await this.verifyAccessTokenUc.execute(token);
      request.user = {
        sub: claims.subject,
        org: claims.organizationId,
        role: claims.role,
        scopes: claims.scopes,
        jti: claims.jti,
      };
      return true;
    } catch (err) {
      this.logger.debug(`JWT verification failed: ${String(err)}`);
      return false;
    }
  }
}
