import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { Public } from '../security/public.decorator';
import { Response } from 'express';
import { GetJwksUseCase } from '../../application/use-cases/get-jwks.use-case';
import { IntrospectTokenUseCase } from '../../application/use-cases/introspect-token.use-case';
import { IssueAccessTokenUseCase } from '../../application/use-cases/issue-access-token.use-case';
import { LoginUseCase } from '../../../authentication/application/use-cases/login.use-case';
import { RefreshTokenGrantUseCase } from '../../application/use-cases/refresh-token-grant.use-case';
import { RevokeTokenUseCase } from '../../application/use-cases/revoke-token.use-case';
import { TokenInspectDto } from './dto/token-inspect.dto';
import { TokenRequestDto } from './dto/token-request.dto';
import { VerifyAppApiKeyUseCase } from '../../../apps/application/use-cases/verify-app-api-key.use-case';

/**
 * Authorization HTTP controller.
 *
 * Public endpoints:
 *
 *   GET  /.well-known/jwks.json
 *     — JWKS document with all currently-verifying signing keys.
 *
 *   POST /v1/oauth/token
 *     — RFC 6749 token endpoint. Supports `password` and `refresh_token`
 *       grants. Returns {access_token, token_type, expires_in,
 *       refresh_token, scope}.
 *
 *   POST /v1/oauth/introspect
 *     — RFC 7662. Returns {active, ...claims}. V1: open endpoint
 *       (the spec recommends resource-server auth; that lands in the
 *       Administration context — Phase 15).
 *
 *   POST /v1/oauth/revoke
 *     — RFC 7009. Always returns 200 per the spec.
 *
 *   POST /v1/oauth/admin/keys/rotate
 *     — Operator-only endpoint to mint a new signing key. Not
 *       authenticated (V1) — relies on network-level ACL in
 *       production. Phase 15 wires admin API-key auth.
 */
@Controller('oauth')
export class OAuthController {
  public constructor(
    private readonly issueAccessTokenUc: IssueAccessTokenUseCase,
    private readonly refreshTokenGrantUc: RefreshTokenGrantUseCase,
    private readonly introspectUc: IntrospectTokenUseCase,
    private readonly revokeUc: RevokeTokenUseCase,
    private readonly getJwksUc: GetJwksUseCase,
    private readonly loginUc: LoginUseCase,
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
  ) {}

  /**
   * Pull the app's `defaultOrgSlug` from the request headers, if
   * present. Mirrors the helper in `AuthController`.
   */
  private async appDefaultOrgSlug(
    appId: string | undefined,
    appSecret: string | undefined,
  ): Promise<string | null> {
    if (!appId || !appSecret) return null;
    const verified = await this.verifyAppApiKeyUc.execute({
      appId: appId.trim(),
      plaintextApiKey: appSecret.trim(),
    });
    return verified?.defaultOrgSlug ?? null;
  }

  @Public()
  @Post('token')
  @HttpCode(HttpStatus.OK)
  public async token(
    @Body() body: TokenRequestDto,
    @Res() res: Response,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
  ) {
    const appDefaultOrgSlug = await this.appDefaultOrgSlug(appId, appSecret);
    if (body.grant_type === 'password') {
      if (!body.username || !body.password) {
        res.status(HttpStatus.BAD_REQUEST).json({
          error: 'invalid_request',
          error_description:
            'username and password are required for grant_type=password',
        });
        return;
      }
      // V1: use the Authentication context's LoginUseCase to mint a
      // session, then immediately issue an access token from the
      // session's user. V1.5: pass appDefaultOrgSlug so the session
      // (and therefore the access token) is scoped to the bound org.
      const loginResult = await this.loginUc.execute({
        email: body.username,
        password: body.password,
        appDefaultOrgSlug,
      });
      const issued = await this.issueAccessTokenUc.execute({
        userId: loginResult.userId,
        organizationSlug:
          loginResult.organizationId ?? appDefaultOrgSlug ?? null,
      });
      res.json({
        access_token: issued.accessToken,
        token_type: 'Bearer',
        expires_in: issued.expiresIn,
        refresh_token: loginResult.refreshToken,
        scope: issued.scopes.join(' '),
      });
      return;
    }

    if (body.grant_type === 'refresh_token') {
      if (!body.refresh_token) {
        res.status(HttpStatus.BAD_REQUEST).json({
          error: 'invalid_request',
          error_description:
            'refresh_token is required for grant_type=refresh_token',
        });
        return;
      }
      const refreshed = await this.refreshTokenGrantUc.execute({
        refreshToken: body.refresh_token,
        organizationSlug: appDefaultOrgSlug,
      });
      res.json({
        access_token: refreshed.accessToken,
        token_type: 'Bearer',
        expires_in: refreshed.expiresIn,
        refresh_token: refreshed.refreshToken,
        scope: refreshed.scopes.join(' '),
      });
      return;
    }

    res.status(HttpStatus.BAD_REQUEST).json({
      error: 'unsupported_grant_type',
    });
  }

  @Public()
  @Post('introspect')
  @HttpCode(HttpStatus.OK)
  public async introspect(@Body() body: TokenInspectDto) {
    return this.introspectUc.execute({
      token: body.token,
      tokenTypeHint: body.token_type_hint,
    });
  }

  @Public()
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  public async revoke(@Body() body: TokenInspectDto): Promise<void> {
    await this.revokeUc.execute({
      token: body.token,
      tokenTypeHint: body.token_type_hint,
    });
  }
}

/**
 * JWKS controller — separate so it can be mounted at the
 * `/.well-known/jwks.json` path which is excluded from the `/v1`
 * prefix in `main.ts`.
 */
@Controller('.well-known')
export class JwksController {
  public constructor(private readonly getJwksUc: GetJwksUseCase) {}

  @Public()
  @Get('jwks.json')
  public async jwks() {
    return this.getJwksUc.execute(new Date());
  }
}
