import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DomainError } from '../../../shared/domain/errors/domain-error';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';
import { AppConfig } from '../../../config/configuration';

export interface VerifyAccessTokenResult {
  subject: string;
  organizationId: string | null;
  role: string | null;
  scopes: ReadonlyArray<string>;
  jti: string;
}

/**
 * Verify an access token and return its claims.
 *
 * V1: throws `authorization.token.invalid` for any failure (signature,
 * expiry, audience, issuer). Resource servers calling this via the
 * introspect endpoint get the same error mapping.
 */
@Injectable()
export class VerifyAccessTokenUseCase {
  public constructor(
    private readonly jwtSigner: JwtSignerService,
    private readonly configService: ConfigService,
  ) {}

  public async execute(token: string): Promise<VerifyAccessTokenResult> {
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

    return {
      subject,
      organizationId: typeof payload.org === 'string' ? payload.org : null,
      role: typeof payload.role === 'string' ? payload.role : null,
      scopes:
        typeof payload.scope === 'string'
          ? payload.scope.split(' ').filter((s) => s.length > 0)
          : [],
      jti: typeof payload.jti === 'string' ? payload.jti : '',
    };
  }
}
