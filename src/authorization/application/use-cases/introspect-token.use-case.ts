import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Session } from '../../../authentication/domain/aggregates/session';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';
import { VerifyAccessTokenUseCase } from './verify-access-token.use-case';

export interface IntrospectTokenInput {
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
}

export interface IntrospectTokenResult {
  active: boolean;
  scope?: string;
  sub?: string;
  org?: string;
  role?: string;
  jti?: string;
  iat?: number;
  exp?: number;
  tokenType?: 'access_token' | 'refresh_token';
}

/**
 * RFC 7662 token introspection.
 *
 * Resource servers call this to check whether a presented token is
 * still valid. Returns an object with `active: true|false` and (when
 * active) the relevant claims. RFC 7662 §2.2 specifies that when the
 * token is NOT active, the response MUST contain only the `active: false`
 * field — no other claims, to avoid leaking information about tokens
 * we couldn't verify.
 *
 * V1 supports JWT access tokens (verified against the signing key)
 * and refresh tokens (verified against the session store).
 */
@Injectable()
export class IntrospectTokenUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    private readonly verifyAccessTokenUc: VerifyAccessTokenUseCase,
  ) {}

  public async execute(
    input: IntrospectTokenInput,
  ): Promise<IntrospectTokenResult> {
    const now = this.clock.now();
    const hint = input.tokenTypeHint ?? 'access_token';

    if (hint === 'access_token') {
      const accessResult = await this.tryAccess(input.token);
      if (accessResult) return accessResult;
      return (await this.tryRefresh(input.token, now)) ?? { active: false };
    }
    const refreshResult = await this.tryRefresh(input.token, now);
    if (refreshResult) return refreshResult;
    return (await this.tryAccess(input.token)) ?? { active: false };
  }

  private async tryAccess(
    token: string,
  ): Promise<IntrospectTokenResult | null> {
    try {
      // V1.7 (audit H-3): VerifyAccessTokenUseCase rejects `typ: 'app'`
      // tokens by default — introspection (RFC 7662) must still report
      // them, so opt in. App tokens are first-class subjects here.
      const claims = await this.verifyAccessTokenUc.execute(token, {
        allowAppTokens: true,
      });
      // Extract `exp`/`iat` from the JWT payload (the second dot-
      // separated segment). We do this inline because jose's
      // `decodeProtectedHeader` only returns the header.
      const payloadBase64 = token.split('.')[1];
      const payloadJson = payloadBase64
        ? Buffer.from(
            payloadBase64.replace(/-/g, '+').replace(/_/g, '/'),
            'base64',
          ).toString('utf8')
        : '{}';
      const payload = JSON.parse(payloadJson) as {
        iat?: number;
        exp?: number;
      };
      return {
        active: true,
        tokenType: 'access_token',
        sub: claims.subject,
        org: claims.organizationId ?? undefined,
        role: claims.role ?? undefined,
        scope: claims.scopes.join(' ') || undefined,
        jti: claims.jti || undefined,
        iat: payload.iat,
        exp: payload.exp,
      };
    } catch {
      return null;
    }
  }

  private async tryRefresh(
    token: string,
    now: Date,
  ): Promise<IntrospectTokenResult | null> {
    const { RefreshTokenHash } =
      await import('../../../authentication/domain/value-objects/refresh-token-hash');
    const presentedHash = await RefreshTokenHash.fromPlaintext(token);
    const session = await this.txRunner.run<Session | null>(async (tx: Tx) =>
      this.sessionRepo.findByRefreshHash(tx, presentedHash.value),
    );
    if (!session || !session.isAliveAt(now)) return null;
    return {
      active: true,
      tokenType: 'refresh_token',
      sub: session.userId.value,
      iat: Math.floor(session.issuedAt.getTime() / 1000),
      exp: Math.floor(session.expiresAt.getTime() / 1000),
    };
  }
}
