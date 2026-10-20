import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Param,
  ParseUUIDPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ListSessionsUseCase } from '../../application/use-cases/list-sessions.use-case';
import { LoginUseCase } from '../../application/use-cases/login.use-case';
import { LogoutUseCase } from '../../application/use-cases/logout.use-case';
import { RefreshSessionUseCase } from '../../application/use-cases/refresh-session.use-case';
import { RevokeSessionUseCase } from '../../application/use-cases/revoke-session.use-case';
import { VerifyAppApiKeyUseCase } from '../../../apps/application/use-cases/verify-app-api-key.use-case';
import { IssueAccessTokenUseCase } from '../../../authorization/application/use-cases/issue-access-token.use-case';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { CurrentUser } from '../../../authorization/interfaces/security/current-user.decorator';
import { Scopes } from '../../../authorization/interfaces/security/scopes.decorator';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { ScopesGuard } from '../../../authorization/interfaces/security/scopes.guard';
import { ThrottleGuard, Throttle } from '../../../common/throttle.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Authentication HTTP controller.
 *
 * Public endpoints (no auth required):
 *
 *   POST /v1/auth/login — body: { email, password, mfaCode? }
 *     No MFA (or valid inline mfaCode): 200
 *     { refreshToken, accessToken, sessionId, userId, familyId,
 *       expiresAt, mfaRequired: false }.
 *     MFA pending: 200 { mfaRequired: true, mfaToken, sessionId } —
 *     NO accessToken, NO refreshToken. mfaToken is a scoped JWT
 *     (scope 'mfa:verify') for POST /v1/identity/mfa/verify.
 *
 *   POST /v1/auth/refresh — body: { refreshToken }
 *     rotates the refresh token; reuse detection mass-revokes the
 *     family (with a 60s idempotent-retry grace window); sessions
 *     whose MFA verification is pending get 401
 *     authentication.mfa.required.
 *
 *   POST /v1/auth/logout — body: { refreshToken }
 *
 * Authenticated endpoints (Bearer JWT):
 *
 *   POST /v1/auth/sessions/:sessionId/revoke
 *   GET  /v1/auth/sessions
 *
 * V1.5: the `X-User-Id` placeholder has been replaced with a real
 * JWT. JwtAuthGuard verifies the bearer token; @CurrentUser() reads
 * the typed principal from req.user.
 */
@Controller('auth')
export class AuthController {
  public constructor(
    private readonly loginUc: LoginUseCase,
    private readonly refreshUc: RefreshSessionUseCase,
    private readonly logoutUc: LogoutUseCase,
    private readonly listSessionsUc: ListSessionsUseCase,
    private readonly revokeSessionUc: RevokeSessionUseCase,
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
    private readonly issueAccessTokenUc: IssueAccessTokenUseCase,
  ) {}

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
  @Throttle(60, 20) // 20 login attempts / minute / IP — pairs with the in-DB lockout
  @UseGuards(ThrottleGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  public async login(
    @Body() body: LoginDto,
    @Ip() ip: string,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
  ) {
    const appDefaultOrgSlug = await this.appDefaultOrgSlug(appId, appSecret);
    const loginResult = await this.loginUc.execute({
      email: body.email,
      password: body.password,
      userAgent: body.userAgent,
      ipAddress: ip,
      appDefaultOrgSlug,
      mfaCode: body.mfaCode,
    });
    // 2026-10-19 audit fix C1: MFA-pending logins return ONLY the
    // scoped mfaToken + sessionId. Handing out a usable refreshToken
    // here (the old behavior) let a password-only attacker walk
    // through /v1/auth/refresh and defeat the second factor entirely.
    if (loginResult.mfaRequired) {
      return {
        mfaRequired: true,
        mfaToken: loginResult.mfaToken,
        sessionId: loginResult.sessionId,
      };
    }
    // V1.5: also issue an access token JWT so the client can call
    // authenticated endpoints without a separate /v1/oauth/token call.
    // The org claim comes from the user's membership (the login use-
    // case already verified the session's org binding). Only the
    // app's default-org SLUG is passed for the pinned-org check —
    // organizationId is a UUID, not a slug, and the slug lookup would
    // 404 on it.
    const issued = await this.issueAccessTokenUc.execute({
      userId: loginResult.userId,
      organizationSlug: appDefaultOrgSlug,
    });
    return {
      ...loginResult,
      accessToken: issued.accessToken,
      expiresIn: issued.expiresIn,
    };
  }

  @Public()
  // 2026-10-19 audit LOW fix: /v1/auth/refresh was unthrottled — a
  // stolen refresh token could be hammered without limit (and the
  // endpoint does argon2 hashing work per attempt).
  @Throttle(60, 30)
  @UseGuards(ThrottleGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  public async refresh(
    @Body() body: RefreshTokenDto,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
  ) {
    const appDefaultOrgSlug = await this.appDefaultOrgSlug(appId, appSecret);
    const refreshResult = await this.refreshUc.execute({
      refreshToken: body.refreshToken,
      appDefaultOrgSlug,
    });
    // V1.5: also issue a fresh access token. The new refresh token
    // is already rotated; the access token follows the same scope.
    const issued = await this.issueAccessTokenUc.execute({
      userId: refreshResult.userId,
      organizationSlug: appDefaultOrgSlug,
    });
    return {
      ...refreshResult,
      accessToken: issued.accessToken,
      expiresIn: issued.expiresIn,
    };
  }

  // `logout` requires the refresh token in the body (no JWT), so it
  // is `@Public()` but the use-case validates the token itself.
  @Public()
  // 2026-10-19 audit LOW fix: /v1/auth/logout was unthrottled.
  @Throttle(60, 30)
  @UseGuards(ThrottleGuard)
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async logout(@Body() body: RefreshTokenDto): Promise<void> {
    await this.logoutUc.execute({ refreshToken: body.refreshToken });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:read')
  @Get('sessions')
  public async listSessions(@CurrentUser() principal: UserPrincipal) {
    return this.listSessionsUc.execute({ userId: principal.userId });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('sessions/:sessionId/revoke')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async revokeSession(
    @CurrentUser() principal: UserPrincipal,
    @Param('sessionId', ParseUUIDPipe) sessionId: string,
  ): Promise<void> {
    // 2026-10-19 audit LOW fix: the endpoint ignored its path param
    // and revoked whatever sessionId was in the body — the DTO and
    // the route disagreed, and a caller revoking `sessions/abc/revoke`
    // with `{ "sessionId": "xyz" }` silently revoked xyz.
    await this.revokeSessionUc.execute({
      sessionId,
      requesterUserId: principal.userId,
    });
  }
}
