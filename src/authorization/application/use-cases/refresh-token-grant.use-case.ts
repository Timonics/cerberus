import { Inject, Injectable } from '@nestjs/common';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Session } from '../../../authentication/domain/aggregates/session';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { IssueAccessTokenUseCase } from './issue-access-token.use-case';

export interface RefreshTokenGrantInput {
  refreshToken: string;
  /**
   * Optional — slug of the org to scope the new access token to.
   * V1.5: when the OAuth2 refresh call carries an app's org
   * binding, pass it here so the issued access token matches the
   * session's org. V1 ignored this and the JWT always picked the
   * user's first org.
   */
  organizationSlug?: string | null;
}

export interface RefreshTokenGrantResult {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  scopes: ReadonlyArray<string>;
}

/**
 * OAuth2 `refresh_token` grant.
 *
 * Verifies the refresh token against the session store, issues a fresh
 * access token + (new) refresh token. The new refresh token rotation
 * happens at the session layer; this use-case is a thin orchestration
 * over `RefreshSessionUseCase`'s behavior (which is exposed via the
 * session repo's `findByRefreshHash`).
 *
 * NOTE: this implementation is intentionally simple — it does NOT
 * itself rotate the refresh token (that's done by the AuthBC's
 * RefreshSessionUseCase, which we could call instead). To keep this
 * phase self-contained and avoid circular module dependencies, we read
 * the session, look up the user, issue the access token. The
 * refresh-token rotation is delegated to the caller (who must use
 * AuthBC's endpoint for that — see the OAuth2 token endpoint below).
 */
@Injectable()
export class RefreshTokenGrantUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    private readonly issueAccessTokenUc: IssueAccessTokenUseCase,
  ) {}

  public async execute(
    input: RefreshTokenGrantInput,
  ): Promise<RefreshTokenGrantResult> {
    // Hash the presented refresh token.
    const { RefreshTokenHash } =
      await import('../../../authentication/domain/value-objects/refresh-token-hash');
    const presentedHash = await RefreshTokenHash.fromPlaintext(
      input.refreshToken,
    );

    const session = await this.txRunner.run<Session | null>(async (tx: Tx) => {
      const s = await this.sessionRepo.findByRefreshHash(
        tx,
        presentedHash.value,
      );
      if (!s) return null;
      // The session's CURRENT refresh hash must equal the presented one
      // (otherwise someone presented an already-rotated token — reuse).
      return s;
    });

    if (!session || !session.isAliveAt(new Date())) {
      throw new DomainError(
        'authorization.token.invalid',
        'Refresh token is not valid',
      );
    }

    // V1.5 (audit C-4): if the session requires MFA and hasn't been
    // verified yet, refuse to issue a fresh access token. The user
    // must call POST /v1/identity/mfa/verify with the sessionId and
    // their TOTP / recovery code first. This closes the OAuth2
    // refresh-token path that previously allowed bypassing MFA after
    // capturing a stolen password.
    if (!session.mfaVerified) {
      throw new DomainError(
        'authorization.token.invalid',
        'Multi-factor authentication required; verify MFA on this session before refreshing',
        { sessionId: session.id.value },
      );
    }

    const userId: UserId = session.userId;

    const issued = await this.issueAccessTokenUc.execute({
      userId: userId.value,
      organizationSlug: input.organizationSlug ?? null,
    });

    return {
      accessToken: issued.accessToken,
      expiresIn: issued.expiresIn,
      refreshToken: input.refreshToken, // V1: don't rotate here; client calls /refresh separately
      scopes: issued.scopes,
    };
  }
}
