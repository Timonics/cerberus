import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
} from '@nestjs/common';
import { ListSessionsUseCase } from '../../application/use-cases/list-sessions.use-case';
import { LoginUseCase } from '../../application/use-cases/login.use-case';
import { LogoutUseCase } from '../../application/use-cases/logout.use-case';
import { RefreshSessionUseCase } from '../../application/use-cases/refresh-session.use-case';
import { RevokeSessionUseCase } from '../../application/use-cases/revoke-session.use-case';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RevokeSessionDto } from './dto/revoke-session.dto';

/**
 * Authentication HTTP controller.
 *
 * Public endpoints (no auth required):
 *
 *   POST /v1/auth/login
 *     — body: { email, password, userAgent?, ipAddress? }
 *     — returns: { refreshToken, sessionId, userId, familyId, expiresAt, mfaRequired }
 *     — Phase 13: also returns an access token (JWT).
 *
 *   POST /v1/auth/refresh
 *     — body: { refreshToken }
 *     — returns: { refreshToken, sessionId, familyId, expiresAt }
 *     — rotates the refresh token; reuse detection mass-revokes the family.
 *
 * Authenticated endpoints (X-User-Id header placeholder for Phase 12
 * JWT auth lands in Phase 13):
 *
 *   POST /v1/auth/logout
 *     — body: { refreshToken }
 *
 *   POST /v1/auth/sessions/:id/revoke
 *     — revokes a specific session (caller must own it).
 *
 *   GET  /v1/auth/sessions
 *     — lists active sessions for the caller.
 */
@Controller('auth')
export class AuthController {
  public constructor(
    private readonly loginUc: LoginUseCase,
    private readonly refreshUc: RefreshSessionUseCase,
    private readonly logoutUc: LogoutUseCase,
    private readonly listSessionsUc: ListSessionsUseCase,
    private readonly revokeSessionUc: RevokeSessionUseCase,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  public async login(@Body() body: LoginDto, @Ip() ip: string) {
    return this.loginUc.execute({
      email: body.email,
      password: body.password,
      userAgent: body.userAgent,
      ipAddress: body.ipAddress ?? ip,
    });
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  public async refresh(@Body() body: RefreshTokenDto) {
    return this.refreshUc.execute({ refreshToken: body.refreshToken });
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async logout(@Body() body: RefreshTokenDto): Promise<void> {
    await this.logoutUc.execute({ refreshToken: body.refreshToken });
  }

  @Get('sessions')
  public async listSessions(@Headers('x-user-id') userId: string) {
    return this.listSessionsUc.execute({ userId });
  }

  @Post('sessions/:sessionId/revoke')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async revokeSession(
    @Headers('x-user-id') requesterUserId: string,
    @Body() body: RevokeSessionDto,
  ): Promise<void> {
    await this.revokeSessionUc.execute({
      sessionId: body.sessionId,
      requesterUserId,
    });
  }
}
