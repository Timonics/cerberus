import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Request } from 'express';
import { VerifyAdminApiKeyUseCase } from '../../application/use-cases/verify-admin-api-key.use-case';
import { DomainError } from '../../../shared/domain';

/**
 * Validates the `Authorization: Bearer *** header against the
 * `AdminApiKeyRepository`. Attaches the verified admin key to the
 * request object as `req.adminKey = { id, role }`.
 *
 * Errors map to:
 *   * Missing header → `GraphQLError('UNAUTHENTICATED')`
 *   * Invalid token  → `GraphQLError('UNAUTHENTICATED')`
 *
 * The admin listener returns HTTP 401 with the corresponding
 * `DomainError.code` via the `DomainErrorFilter`.
 */
@Injectable()
export class AdminApiKeyGuard implements CanActivate {
  public constructor(
    private readonly verifyAdminApiKey: VerifyAdminApiKeyUseCase,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new DomainError(
        'admin.auth.missing',
        'Missing or malformed Authorization header on admin request',
      );
    }
    const token = header.substring('Bearer '.length).trim();
    if (!token) {
      throw new DomainError('admin.auth.missing', 'Empty bearer token');
    }
    let claims: Awaited<ReturnType<VerifyAdminApiKeyUseCase['execute']>>;
    try {
      claims = await this.verifyAdminApiKey.execute({
        plaintextToken: token,
      });
    } catch (err) {
      if (err instanceof DomainError) throw err;
      throw new DomainError('admin.auth.invalid', 'Admin auth failed');
    }
    if (!claims) {
      throw new DomainError('admin.auth.invalid', 'Invalid admin API key');
    }
    (req as Request & { adminKey: typeof claims }).adminKey = claims;
    return true;
  }
}
