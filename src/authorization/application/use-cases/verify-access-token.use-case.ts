import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DomainError } from '../../../shared/domain/errors/domain-error';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import { AppConfig } from '../../../config/configuration';

export interface VerifyAccessTokenOptions {
  /**
   * V1.7 (audit H-3): app-bound tokens (`typ: 'app'`, minted by the
   * client_credentials grant with `sub = appId`) are REJECTED by
   * default — they must never authenticate as a user principal.
   * Only token-introspection-style callers (the GraphQL
   * `Authorization.verifyAccessToken` query, which exists precisely
   * so resource servers can inspect whichever token they received)
   * opt in by setting this to true.
   */
  allowAppTokens?: boolean;
}

export interface VerifyAccessTokenResult {
  subject: string;
  organizationId: string | null;
  role: string | null;
  scopes: ReadonlyArray<string>;
  jti: string;
  /**
   * The JWT `typ` claim ('user' / 'app'), or null when the token
   * predates the claim. User-bound tokens issued by current
   * versions carry `typ: 'user'`; app-bound tokens always carry
   * `typ: 'app'`.
   */
  tokenType: string | null;
  /** `iss` claim as verified. */
  issuer: string | null;
  /** `aud` claim as verified. */
  audience: string | null;
  /** `iat` claim, epoch seconds. */
  issuedAt: number | null;
  /** `exp` claim, epoch seconds. */
  expiresAt: number | null;
}

/**
 * Verify an access token and return its claims.
 *
 * V1: throws `authorization.token.invalid` for any failure (signature,
 * expiry, audience, issuer). Resource servers calling this via the
 * introspect endpoint get the same error mapping.
 *
 * V1.7 (audit H-3): rejects `typ: 'app'` tokens unless the caller
 * passes `{ allowAppTokens: true }`. Tokens with no `typ` claim are
 * treated as user tokens (legacy user-bound tokens predate the
 * claim — see IssueAccessTokenUseCase).
 */
@Injectable()
export class VerifyAccessTokenUseCase {
  public constructor(
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
  ) {}

  public async execute(
    token: string,
    options?: VerifyAccessTokenOptions,
  ): Promise<VerifyAccessTokenResult> {
    const issuer =
      this.configService.getOrThrow<AppConfig['jwt']['issuer']>('jwt.issuer');
    const audience = this.configService.getOrThrow<
      AppConfig['jwt']['audienceDefault']
    >('jwt.audienceDefault');

    let payload;
    try {
      payload = await this.jwtSigner.verifyAccessToken({
        token,
        issuer,
        audience,
      });
    } catch {
      throw new DomainError(
        'authorization.token.invalid',
        'Access token is invalid or expired',
      );
    }

    const subject = payload.sub;
    if (typeof subject !== 'string') {
      throw new DomainError(
        'authorization.token.invalid',
        'Token missing subject',
      );
    }

    const tokenType = typeof payload.typ === 'string' ? payload.typ : null;
    if (tokenType === 'app' && options?.allowAppTokens !== true) {
      throw new DomainError(
        'authorization.token.invalid',
        'Token is not valid for this endpoint',
      );
    }

    return {
      subject,
      organizationId: typeof payload.org === 'string' ? payload.org : null,
      role: typeof payload.role === 'string' ? payload.role : null,
      scopes:
        typeof payload.scope === 'string'
          ? payload.scope.split(' ').filter((s) => s.length > 0)
          : [],
      jti: typeof payload.jti === 'string' ? payload.jti : '',
      tokenType,
      issuer: typeof payload.iss === 'string' ? payload.iss : null,
      audience: typeof payload.aud === 'string' ? payload.aud : null,
      issuedAt: typeof payload.iat === 'number' ? payload.iat : null,
      expiresAt: typeof payload.exp === 'number' ? payload.exp : null,
    };
  }
}
