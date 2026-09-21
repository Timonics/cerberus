import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
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
import { RevokeSessionDto } from './dto/revoke-session.dto';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { CurrentUser } from '../../../authorization/interfaces/security/current-user.decorator';
import { Scopes } from '../../../authorization/interfaces/security/scopes.decorator';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { ScopesGuard } from '../../../authorization/interfaces/security/scopes.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Authentication HTTP controller.
 *
 * Public endpoints (no auth required):
 *
 *   POST /v1/auth/login — body: { email, password, ... }
 *     returns: { refreshToken, sessionId, userId, familyId, expiresAt, mfaRequired }
 *     plus an `accessToken` (JWT) when MFA is not required.
 *
 *   POST /v1/auth/refresh — body: { refreshToken }
 *     rotates the refresh token; reuse detection mass-revokes the family.
 *
 *   POST /v1/auth/logout — body: { refreshToken }
 *
 * Authenticated endpoints (Bearer JWT):
 *
 *   POST /v1/auth/sessions/:id/revoke
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
      ipAddress: body.ipAddress ?? ip,
      appDefaultOrgSlug,
    });
    // V1.5: also issue an access token JWT so the client can call
    // authenticated endpoints without a separate /v1/oauth/token call.
    // The token's org claim is pinned to the login result's org
    // (or the app's default org when the user has no membership).
    if (!loginResult.mfaRequired) {
      const issued = await this.issueAccessTokenUc.execute({
        userId: loginResult.userId,
        organizationSlug:
          loginResult.organizationId ?? appDefaultOrgSlug ?? null,
      });
      return {
        ...loginResult,
        accessToken: issued.accessToken,
        expiresIn: issued.expiresIn,
      };
    }
    return loginResult;
  }

  @Public()
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
    @Body() body: RevokeSessionDto,
  ): Promise<void> {
    await this.revokeSessionUc.execute({
      sessionId: body.sessionId,
      requesterUserId: principal.userId,
    });
  }
}
