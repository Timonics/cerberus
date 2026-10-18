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
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import { Membership } from '../../../identity/domain/aggregates/membership';
import { Scope, serializeScopes } from '../../domain/value-objects/scope';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../../identity/domain/ports/membership.repository.port';
import { AppConfig } from '../../../config/configuration';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

export interface IssueAccessTokenInput {
  userId: string;
  /**
   * Optional — slug of the org to scope the access token to. V1 left
   * this off and always picked the user's first membership; V1.5 lets
   * the caller pin the token to a specific org (e.g. the org the
   * session is scoped to). When omitted, the user's first membership
   * is used (V1 backward-compat).
   */
  organizationSlug?: string | null;
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
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
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
      // V1.5: when the caller pins the token to a specific org, look up
      // that org first and verify the user is actually a member.
      if (input.organizationSlug && membership) {
        const targetOrgSlug = OrgSlug.create(input.organizationSlug);
        const org = await this.organizationRepo.findBySlug(tx, targetOrgSlug);
        if (org && !org.id.equals(membership.organizationId)) {
          throw new DomainError(
            'authentication.app_membership_required',
            'User is not a member of the requested organization',
            {
              userId: userId.value,
              requestedOrgSlug: input.organizationSlug,
            },
          );
        }
        if (!org) {
          // The slug doesn't exist at all — treat as no membership for
          // that org; fall back to the user's existing membership so the
          // token can still be issued (legacy compat).
          void 0;
        }
      }
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

    // V1.5 audit: write `authorization.token.minted` so security
    // teams can see who got a token, with what scopes, and from
    // which org. (If the mint throws, no row is written — we
    // deliberately only audit successful mints.)
    await this.recordAuditEventUc.execute({
      userId: input.userId,
      eventType: 'authorization.token.minted',
      payload: {
        scopes: scopes.map((s) => s.value),
        organizationSlug: input.organizationSlug ?? null,
        ttlSeconds,
      },
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
      // V1.7 audit fix #11: ADMIN/OWNER can introspect arbitrary
      // tokens. MEMBER cannot — the prior audit noted that
      // /v1/oauth/introspect was guarded only by JwtAuthGuard,
      // letting any valid JWT enumerate all live tokens.
      return [
        ...base,
        Scope.create('auth:write'),
        Scope.create('org:admin'),
        Scope.create('introspect:read'),
      ];
    }
    return base;
  }
}
