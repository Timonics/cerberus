import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Public } from '../security/public.decorator';
import { JwtAuthGuard } from '../security/jwt-auth.guard';
import { Throttle, ThrottleGuard } from '../../../common/throttle.guard';
import { Scopes } from '../security/scopes.decorator';
import { ScopesGuard } from '../security/scopes.guard';
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
import { IssueClientCredentialsAccessTokenUseCase } from '../../application/use-cases/issue-client-credentials-access-token.use-case';

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
    private readonly issueClientCredentialsUc: IssueClientCredentialsAccessTokenUseCase,
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
  // V1.7 audit fix #2: the OAuth password grant bypasses the
  // /v1/auth/login ThrottleGuard (which gates the LoginUseCase
  // directly). An attacker can keep retrying credentials via
  // this endpoint and dodge the in-DB lockout + per-IP rate limit.
  // Apply the same 20/min/IP cap here. The client_credentials
  // and refresh_token branches are also under this guard — same
  // throttle for all grants (a per-grant key would be more
  // sophisticated; the V2 followup is `Throttle per (grant_type, ip)`).
  @Throttle(60, 20)
  @UseGuards(ThrottleGuard)
  @Post('token')
  @HttpCode(HttpStatus.OK)
  public async token(
    @Body() body: TokenRequestDto,
    @Res() res: Response,
    @Ip() ip: string,
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
      // 2026-10-19 audit fix H-8: pass the request IP so the lockout
      // key doesn't collapse to `email:0.0.0.0` (which split counters
      // across transports and destroyed per-IP forensics). The mfaCode
      // (2026-10-19 audit fix C1) lets first-party clients complete
      // MFA inline — same contract as POST /v1/auth/login.
      const loginResult = await this.loginUc.execute({
        email: body.username,
        password: body.password,
        ipAddress: ip,
        appDefaultOrgSlug,
        mfaCode: body.mfa_code,
      });
      // V1.5 (audit C-4) + 2026-10-19 audit fixes C1/H-12: if the
      // session requires MFA and no valid inline code was supplied,
      // refuse to issue tokens. The response is a documented
      // non-standard extension of RFC 6749: 403 with
      // `error: 'mfa_required'` plus a scoped `mfa_token` (JWT,
      // scope 'mfa:verify', TTL MFA_PENDING_TOKEN_TTL) that the client
      // presents to POST /v1/identity/mfa/verify. No refresh_token and
      // no access_token are returned on this path.
      if (loginResult.mfaRequired) {
        res.status(HttpStatus.FORBIDDEN).json({
          error: 'mfa_required',
          error_description:
            'Multi-factor authentication required; present mfa_token at POST /v1/identity/mfa/verify (or supply mfa_code with the password grant)',
          mfa_token: loginResult.mfaToken,
          session_id: loginResult.sessionId,
        });
        return;
      }
      // The org claim comes from the user's membership (the login
      // use-case already enforced the app binding). Only the app's
      // default-org SLUG feeds the pinned-org check — session
      // organizationId is a UUID, not a slug.
      const issued = await this.issueAccessTokenUc.execute({
        userId: loginResult.userId,
        organizationSlug: appDefaultOrgSlug,
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

    // V1.6 client_credentials grant (RFC 6749 §4.4). Service-to-
    // service: Charon / an org's backend / a CI pipeline presents
    // their App's `client_id` (= App UUID) + `client_secret`
    // (plaintext API key from register-time) and gets back a JWT
    // signed with the Cerberus signing key. The JWT carries
    // `typ: 'app'` so resource servers can distinguish it from
    // user-bound tokens without a separate apps-by-id cache.
    //
    // No refresh_token in the response — apps re-mint when
    // needed. No MFA — apps don't have phones.
    //
    // The `X-Cerberus-App-Id` + `X-Cerberus-App-Secret` headers
    // are accepted as an alternative transport (same shape as
    // register/login) for callers that already have those wired up.
    if (body.grant_type === 'client_credentials') {
      const clientId = body.client_id ?? appId ?? '';
      const clientSecret = body.client_secret ?? appSecret ?? '';
      if (!clientId || !clientSecret) {
        res.status(HttpStatus.BAD_REQUEST).json({
          error: 'invalid_request',
          error_description:
            'client_id and client_secret are required for grant_type=client_credentials',
        });
        return;
      }
      const issued = await this.issueClientCredentialsUc.execute({
        clientId,
        clientSecret,
        scope: body.scope ?? null,
      });
      res.json({
        access_token: issued.accessToken,
        token_type: 'Bearer',
        expires_in: issued.expiresIn,
        scope: issued.scope,
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
  // V1.7 audit fix #11: gate on `introspect:read` scope. Prior to
  // this, /v1/oauth/introspect was guarded only by JwtAuthGuard,
  // meaning any valid JWT could enumerate all live tokens. Now
  // only ADMIN/OWNER-scoped tokens (which have the
  // `introspect:read` scope) can introspect. MEMBER tokens get
  // 401 insufficient_scope.
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('introspect:read')
  @Post('introspect')
  @HttpCode(HttpStatus.OK)
  public async introspect(@Body() body: TokenInspectDto) {
    return this.introspectUc.execute({
      token: body.token,
      tokenTypeHint: body.token_type_hint,
    });
  }

  // V1.5 (audit C3): revoke also requires Bearer auth. V1.7
  // (audit #11): also requires `introspect:read` scope (revoke
  // and introspect are paired — a token oracle that can mint
  // should be able to revoke).
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('introspect:read')
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
