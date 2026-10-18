import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AppConfig } from '../../config/configuration';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../shared/domain';
import {
  ADMIN_API_KEY_REPOSITORY,
  AdminApiKeyRepository,
} from '../../administration/domain/ports/admin-api-key.repository.port';
import {
  ADMIN_API_KEY_HASHER,
  AdminApiKeyHasher,
} from '../../administration/infrastructure/security/argon2-admin-api-key.hasher';
import { AdminApiKeyLookupTokenService } from '../../administration/infrastructure/security/admin-api-key-lookup-token.service';

/**
 * V1.7: production-gate for self-service endpoints.
 *
 * `register` (POST /v1/apps) and similar dev-friendly endpoints are
 * `@Public` in dev/staging so an operator can spin up an app
 * without first minting an admin key. In production that same
 * openness is a vulnerability — anyone who reaches the public
 * surface could register a new app and get an API key to the
 * auth subsystem.
 *
 * This guard closes the gap: in `NODE_ENV=production` it requires
 * a valid `Authorization: Bearer <admin-key>` header. In dev it
 * passes through (fails open). The behavior is configurable via
 * `security.requireAdminForRegistration` so an operator can
 * tighten the gate in staging as well.
 *
 * The guard depends on `VerifyAdminApiKeyUseCase` from the
 * `administration` context — that's a cross-context dep, but
 * AdminApiKey has no public equivalent and this is the only
 * surface where prod-side self-service registration is exposed.
 */
@Injectable()
export class ProductionAdminGuard implements CanActivate {
  private readonly logger = new Logger(ProductionAdminGuard.name);
  public constructor(
    private readonly config: ConfigService<Record<string, unknown>>,
    @Inject(ADMIN_API_KEY_REPOSITORY)
    private readonly adminKeyRepo: AdminApiKeyRepository,
    @Inject(ADMIN_API_KEY_HASHER)
    private readonly hasher: AdminApiKeyHasher,
    private readonly lookupService: AdminApiKeyLookupTokenService,
    @Inject(TRANSACTION_RUNNER)
    private readonly txRunner: TransactionRunner,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const nodeEnv = this.config.get<AppConfig['nodeEnv']>('nodeEnv');
    const security = this.config.get<AppConfig['security']>('security');
    const requireAdmin = security?.requireAdminForRegistration ?? false;
    // Pass-through outside production unless explicitly forced on.
    if (nodeEnv !== 'production' && !requireAdmin) {
      return true;
    }
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      this.logger.warn(
        `Blocked unauthenticated self-service request to ${req.method} ${req.url} ` +
          `(NODE_ENV=${nodeEnv})`,
      );
      throw new DomainError(
        'admin.auth.missing',
        'Admin Authorization required in production',
      );
    }
    const token = header.substring('Bearer '.length).trim();
    if (!token) {
      throw new DomainError('admin.auth.missing', 'Empty bearer token');
    }
    // V1.7: use the HMAC-based lookup token (V1.5 hot path) for
    // an O(1) DB scan — the same mechanism AdminApiKeyGuard uses
    // today. The repository returns null for unknown / revoked /
    // expired keys, so we don't even need a separate `revokedAt`
    // check. argon2id verify is then a single hasher.verify on
    // the matched key.
    const lookupToken = this.lookupService.compute(token);
    const claims = await this.txRunner.run((tx: Tx) =>
      this.adminKeyRepo.findActiveByLookupToken(tx, lookupToken),
    );
    if (!claims) {
      throw new DomainError('admin.auth.invalid', 'Invalid admin API key');
    }
    // Belt-and-suspenders: argon2 verify the plaintext against
    // the stored hash. The lookup-token is HMAC (fast) but only
    // the argon2 verify proves the caller actually has the
    // plaintext (HMAC is deterministic, so an attacker with the
    // lookup-secret could in principle forge a token — but the
    // attacker would also need to satisfy the argon2 verify).
    const ok = await this.hasher.verify(claims.keyHash, token);
    if (!ok) {
      throw new DomainError('admin.auth.invalid', 'Invalid admin API key');
    }
    return true;
  }
}
