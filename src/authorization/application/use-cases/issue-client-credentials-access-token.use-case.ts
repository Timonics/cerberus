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
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../../apps/domain/ports/app.repository.port';
import { Argon2AppApiKeyHasher } from '../../../apps/infrastructure/security/argon2-app-api-key.hasher';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import { AppConfig } from '../../../config/configuration';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { parseScopeList } from '../../../apps/domain/aggregates/app';

export interface IssueClientCredentialsInput {
  /** App UUID (the `client_id` field of the OAuth2 grant). */
  clientId: string;
  /** Plaintext API key (the `client_secret`). */
  clientSecret: string;
  /** Space-separated scopes requested by the caller. Optional. */
  scope?: string | null;
}

export interface IssueClientCredentialsResult {
  accessToken: string;
  expiresIn: number;
  /** Space-separated scopes actually granted (intersection of request + app allowlist). */
  scope: string;
}

/**
 * V1.6 OAuth2 client_credentials grant (RFC 6749 §4.4).
 *
 * The "service-to-service" flow:
 *
 *   1. Caller (An org's backend, a CI pipeline) sends its
 *      Cerberus-issued `client_id` (App UUID) + `client_secret`
 *      (the plaintext key returned at register-time, kept in the
 *      org's secret store).
 *   2. Cerberus looks up the App by `client_id`, verifies the
 *      plaintext against the stored argon2id hash, checks that
 *      both the app and the key are alive (not revoked / not expired).
 *   3. Resolves the App's `defaultOrgSlug` → `Organization` (the
 *      tenant the token is scoped to). Apps without a binding
 *      mint tokens without an `org` claim — useful for tenant-
 *      agnostic endpoints like JWKS or health probes.
 *   4. Downgrades the caller's requested `scope` to the
 *      intersection with `App.allowedScopes` (RFC 6749 §3.3:
 *      the server is the authority on what the client may request).
 *      Empty allowlist = empty scope (the app authenticates but
 *      cannot do anything).
 *   5. Signs an RS256 JWT carrying the App's identity
 *      (`sub = appId`, `typ = 'app'`, `appId`, `scope`, optional
 *      `org`) with the current signing key.
 *   6. Audits `apps.token.issued` (no `userId` in the audit
 *      schema sense — apps don't have users — the app UUID
 *      goes in the audit `userId` column which is free-form).
 *
 * Returns: `{ access_token, token_type: 'Bearer', expires_in,
 * scope }`. **No refresh_token** — apps re-mint when needed.
 *
 * Error mapping (mirrors OAuth2 §5.2):
 *   * unknown client_id / wrong client_secret / revoked key /
 *     revoked app / expired key → `app.not_found` (kept
 *     intentionally ambiguous — RFC 6749 §5.2 says "invalid_grant"
 *     for both bad client_id AND bad client_secret; we use the
 *     same domain error so we don't leak which one was wrong).
 *
 * Why not reuse `IssueAccessTokenUseCase`? That use-case requires a
 * `userId` and computes scope from the user's role. App-bound tokens
 * have no user, no role, and a different scope source. Keeping the
 * flows separate is clearer than overloading one use-case with a
 * discriminated union on `actor: 'user' | 'app'`.
 */
@Injectable()
export class IssueClientCredentialsAccessTokenUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(APP_REPOSITORY) private readonly appRepo: AppRepository,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly orgRepo: OrganizationRepository,
    private readonly hasher: Argon2AppApiKeyHasher,
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: IssueClientCredentialsInput,
  ): Promise<IssueClientCredentialsResult> {
    if (!input.clientId || !input.clientSecret) {
      throw new DomainError(
        'app.not_found',
        'Invalid client credentials',
      );
    }
    const ttlSeconds =
      this.configService.getOrThrow<AppConfig['jwt']['accessTokenTtl']>(
        'jwt.accessTokenTtl',
      );
    const issuer =
      this.configService.getOrThrow<AppConfig['jwt']['issuer']>('jwt.issuer');
    const audience = this.configService.getOrThrow<
      AppConfig['jwt']['audienceDefault']
    >('jwt.audienceDefault');

    const { token, scope, app, orgUuid } = await this.txRunner.run<{
      token: string;
      scope: string;
      app: { id: string; name: string; allowedScopes: string };
      orgUuid: string | null;
    }>(async (tx: Tx) => {
      // Step 1: look up the App by client_id (the App UUID). The
      // repository returns null if the app doesn't exist OR is
      // revoked; both map to the same domain error to avoid
      // leaking which one was wrong (RFC 6749 §5.2).
      const app = await this.appRepo.findById(tx, input.clientId);
      if (!app || app.revokedAt !== null || !app.currentKey) {
        throw new DomainError(
          'app.not_found',
          'Invalid client credentials',
        );
      }
      // Step 3: argon2 verify. This is the only source of truth
      // for "is this plaintext the right secret" — argon2 salts
      // each hash so we can't pre-compute a lookup index.
      const ok = await this.hasher.verify(
        app.currentKey.keyHash,
        input.clientSecret,
      );
      if (!ok) {
        throw new DomainError(
          'app.not_found',
          'Invalid client credentials',
        );
      }
      // Belt-and-suspenders: catch the key-vs-app race window where
      // the key was alive at find-time but expired by the time we
      // reached here (microseconds, but cheap).
      if (!app.currentKey.isAliveAt(this.clock.now())) {
        throw new DomainError(
          'app.not_found',
          'Invalid client credentials',
        );
      }

      // Step 4: resolve the org from `defaultOrgSlug`. If the slug
      // doesn't resolve (stale or typo at register-time), fall
      // through with no org claim — the token still mints and
      // works on tenant-agnostic endpoints; tenant-gated endpoints
      // will 403.
      let orgUuid: string | null = null;
      if (app.defaultOrgSlug !== null && app.defaultOrgSlug.length > 0) {
        const org = await this.orgRepo.findBySlug(
          tx,
          OrgSlug.create(app.defaultOrgSlug),
        );
        if (org) {
          orgUuid = org.id.value;
        }
      }

      // Step 5: scope downgrade. Empty allowlist = empty scope.
      const allowedScopes = parseScopeList(app.allowedScopes);
      const requestedScopes = (input.scope ?? '')
        .split(' ')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const granted = requestedScopes.filter((s) =>
        allowedScopes.includes(s),
      );
      const scopeString = granted.join(' ');

      // Step 6: sign.
      const key = await this.keyRepo.getCurrent(tx);
      if (!key.canSign()) {
        throw new DomainError(
          'authorization.token.invalid',
          'No active signing key available',
        );
      }
      const payload: Record<string, unknown> = {
        sub: app.id,
        // V1.6: explicit `typ` claim so resource servers can
        // distinguish app-bound tokens from user-bound without a
        // separate apps-by-id cache. Existing user-bound tokens
        // (password + refresh_token grants) keep the default
        // `typ: 'user'` — see IssueAccessTokenUseCase.
        typ: 'app',
        appId: app.id,
        org: orgUuid,
        role: null,
        scope: scopeString,
        jti: this.idGenerator.generate(),
      };

      const tokenStr = await this.jwtSigner.sign({
        payload,
        privatePem: key.privatePem,
        kid: key.kid,
        issuer,
        audience,
        ttlSeconds,
      });

      return {
        token: tokenStr,
        scope: scopeString,
        app: { id: app.id, name: app.name, allowedScopes: app.allowedScopes },
        orgUuid,
      };
    });

    void this.clock; // kept for symmetry with the other token-issuing use-cases

    // Step 7: audit. The `userId` column is free-form text — apps
    // don't have User UUIDs, but the column accepts the app UUID.
    await this.recordAuditEventUc.execute({
      userId: app.id,
      eventType: 'apps.token.issued',
      payload: {
        appId: app.id,
        appName: app.name,
        organizationId: orgUuid,
        scopes: scope ? scope.split(' ').filter(Boolean) : [],
        ttlSeconds,
        grantType: 'client_credentials',
      },
    });

    return {
      accessToken: token,
      expiresIn: ttlSeconds,
      scope,
    };
  }
}