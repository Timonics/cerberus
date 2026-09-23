import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Public } from '../security/public.decorator';
import { JwtAuthGuard } from '../security/jwt-auth.guard';
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
 *     — RFC 7662. V1.5: now requires Bearer auth (was public in V1).
 *       Resource servers authenticate with their own access token
 *       (or, in V1, with an admin API key — V2 will add a dedicated
 *       `introspect` scope).
 *     — Returns {active, ...claims}.
 *
 *   POST /v1/oauth/revoke
 *     — RFC 7009. V1.5: now requires Bearer auth (was public in V1).
 *
 *   POST /admin/keys/rotate  (moved to AdminController — see
 *     src/administration/interfaces/http/oauth-admin.controller.ts)
 *
 * V1.5 fix (audit C3): the introspect + revoke endpoints are now behind
 * `JwtAuthGuard`. RFC 7662 §2.1 requires introspection to be
 * authenticated; an unauthenticated endpoint enables token oracles and
 * DoS-via-revoke. Until we ship dedicated resource-server credentials
 * (V2), we accept a JWT bearer token as proof of identity. A
 * resource server's JWT is the easiest path — they already have one.
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
      // V1.5 (audit C-4): if the session requires MFA, refuse to
      // issue an access token via the OAuth password grant. The user
      // must use the REST /v1/auth/login endpoint (which returns
      // mfaRequired: true) or the REST /v1/identity/mfa/verify flow.
      // Without this, a stolen password is sufficient to mint a JWT.
      if (loginResult.mfaRequired) {
        res.status(HttpStatus.FORBIDDEN).json({
          error: 'mfa_required',
          error_description:
            'Multi-factor authentication required; call POST /v1/auth/login or POST /v1/identity/mfa/verify first',
          session_id: loginResult.sessionId,
        });
        return;
      }
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

  // V1.5 (audit C3): introspect now requires a valid Bearer token.
  // The guard authenticates the resource server, then this method
  // introspects the supplied token. We don't enforce a specific scope
  // here — V2 will add `introspect:read` scope — because V1 resource
  // servers only have full access tokens. Requiring ANY valid token is
  // still strictly better than no auth at all.
  @UseGuards(JwtAuthGuard)
  @Post('introspect')
  @HttpCode(HttpStatus.OK)
  public async introspect(@Body() body: TokenInspectDto) {
    return this.introspectUc.execute({
      token: body.token,
      tokenTypeHint: body.token_type_hint,
    });
  }

  // V1.5 (audit C3): revoke also requires Bearer auth.
  @UseGuards(JwtAuthGuard)
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
