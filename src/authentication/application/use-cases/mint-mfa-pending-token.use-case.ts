import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { AppConfig } from '../../../config/configuration';
import { JwtSignerService } from '../../../authorization/infrastructure/crypto/jwt-signer.service';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../../authorization/domain/ports/signing-key.repository.port';

export interface MintMfaPendingTokenInput {
  /** The user who completed the first factor. */
  userId: string;
  /** The session awaiting MFA verification. */
  sessionId: string;
}

/**
 * Mint the MFA-pending JWT returned by `POST /v1/auth/login` when the
 * user has MFA enabled but has not (or not yet) supplied the second
 * factor.
 *
 * 2026-10-19 audit fix C1: closing the MFA bypass requires a scoped
 * credential the pending user can present to
 * `POST /v1/identity/mfa/verify` (which is JWT-gated). The token:
 *
 *   * is signed by the same `JwtSignerService` as access tokens
 *     (RS256, current signing key);
 *   * carries `scope: 'mfa:verify'` so resource servers reject it for
 *     anything else;
 *   * carries `sub` = userId and `sid` = sessionId so the verify
 *     endpoint can bind the challenge to the pending session;
 *   * lives for `MFA_PENDING_TOKEN_TTL` seconds (default 600).
 *
 * It is NOT a refresh token: it cannot be exchanged at /v1/auth/refresh
 * and no refresh token is issued until MFA verification completes.
 */
@Injectable()
export class MintMfaPendingTokenUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
  ) {}

  public async execute(input: MintMfaPendingTokenInput): Promise<string> {
    const ttlSeconds = this.configService.getOrThrow<
      AppConfig['mfa']['pendingTokenTtlSeconds']
    >('mfa.pendingTokenTtlSeconds');
    const issuer =
      this.configService.getOrThrow<AppConfig['jwt']['issuer']>('jwt.issuer');
    const audience = this.configService.getOrThrow<
      AppConfig['jwt']['audienceDefault']
    >('jwt.audienceDefault');

    return this.txRunner.run<string>(async (tx: Tx) => {
      const key = await this.keyRepo.getCurrent(tx);
      if (!key.canSign()) {
        throw new DomainError(
          'authorization.token.invalid',
          'No active signing key available',
        );
      }
      return this.jwtSigner.sign({
        payload: {
          // V1.7 (audit H-3): user-bound token — guards discriminate
          // on `typ` and reject `typ: 'app'` on user routes.
          typ: 'user',
          sub: input.userId,
          sid: input.sessionId,
          scope: 'mfa:verify',
        },
        privatePem: key.privatePem,
        kid: key.kid,
        issuer,
        audience,
        ttlSeconds,
      });
    });
  }
}
