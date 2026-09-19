import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CLOCK,
  Clock,
  DomainError,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { Role } from '../../../identity/domain/value-objects/role';
import { Membership } from '../../../identity/domain/aggregates/membership';
import { Scope, serializeScopes } from '../../domain/value-objects/scope';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../../identity/domain/ports/membership.repository.port';
import { AppConfig } from '../../../config/configuration';

export interface IssueAccessTokenInput {
  userId: string;
  /** Optional — scopes to include. Defaults to the role's allowed scopes. */
  scopes?: ReadonlyArray<Scope>;
}

export interface IssueAccessTokenResult {
  accessToken: string;
  expiresIn: number;
  scopes: ReadonlyArray<string>;
}

/**
 * Issue an access token (JWT) for the given user.
 *
 * Looks up the user's role via `MembershipRepository`, picks scopes
 * based on that role, signs a JWT with the current signing key.
 *
 * Scope rules:
 *   * `OWNER`  → auth:read, auth:write, org:admin
 *   * `ADMIN`  → auth:read, auth:write, org:admin
 *   * `MEMBER` → auth:read, auth:write
 *   * no membership → auth:read only (defensive)
 *
 * Caller-supplied scopes are intersected with the role's allowed set
 * (OAuth2 scope-downgrade rule).
 */
@Injectable()
export class IssueAccessTokenUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
  ) {
    // Silence unused-import for Clock — kept for future use (token
    // timestamps) and to match the parameter shape of other use-cases.
    void this.clock;
  }

  public async execute(
    input: IssueAccessTokenInput,
  ): Promise<IssueAccessTokenResult> {
    const userId = UserId.create(input.userId);
    const ttlSeconds =
      this.configService.getOrThrow<AppConfig['jwt']['accessTokenTtl']>(
        'jwt.accessTokenTtl',
      );
    const issuer =
      this.configService.getOrThrow<AppConfig['jwt']['issuer']>('jwt.issuer');
    const audience = this.configService.getOrThrow<
      AppConfig['jwt']['audienceDefault']
    >('jwt.audienceDefault');

    const { token, scopes } = await this.txRunner.run<{
      token: string;
      scopes: ReadonlyArray<Scope>;
    }>(async (tx: Tx) => {
      const membership = await this.membershipRepo.findByUserId(tx, userId);
      const scopes = this.scopesFor(membership, input.scopes);

      const key = await this.keyRepo.getCurrent(tx);
      if (!key.canSign()) {
        throw new DomainError(
          'authorization.token.invalid',
          'No active signing key available',
        );
      }

      const payload: Record<string, unknown> = {
        sub: userId.value,
        org: membership?.organizationId.value ?? null,
        role: membership?.role.value ?? null,
        scope: serializeScopes(scopes),
        jti: this.idGenerator.generate(),
      };

      const token = await this.jwtSigner.sign({
        payload,
        privatePem: key.privatePem,
        kid: key.kid,
        issuer,
        audience,
        ttlSeconds,
      });
      return { token, scopes };
    });

    return {
      accessToken: token,
      expiresIn: ttlSeconds,
      scopes: scopes.map((s) => s.value),
    };
  }

  private scopesFor(
    membership: Membership | null,
    requested: ReadonlyArray<Scope> | undefined,
  ): ReadonlyArray<Scope> {
    const allowed = this.allowedScopesFor(membership);
    if (!requested || requested.length === 0) {
      return allowed;
    }
    return requested.filter((s) => allowed.some((a) => a.equals(s)));
  }

  private allowedScopesFor(
    membership: Membership | null,
  ): ReadonlyArray<Scope> {
    const base = [Scope.create('auth:read')];
    if (!membership) return base;
    if (membership.role.equals(Role.create('MEMBER'))) {
      return [...base, Scope.create('auth:write')];
    }
    if (
      membership.role.equals(Role.create('ADMIN')) ||
      membership.role.equals(Role.create('OWNER'))
    ) {
      return [...base, Scope.create('auth:write'), Scope.create('org:admin')];
    }
    return base;
  }
}
