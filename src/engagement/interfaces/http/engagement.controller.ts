import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ConfirmEmailVerificationUseCase } from '../../application/use-cases/confirm-email-verification.use-case';
import { ConfirmPasswordResetUseCase } from '../../application/use-cases/confirm-password-reset.use-case';
import { GetAuditLogForUserUseCase } from '../../application/use-cases/get-audit-log-for-user.use-case';
import { RequestEmailVerificationUseCase } from '../../application/use-cases/request-email-verification.use-case';
import { RequestPasswordResetUseCase } from '../../application/use-cases/request-password-reset.use-case';
import { EmailVerificationConfirmDto } from './dto/email-verification-confirm.dto';
import { PasswordResetConfirmDto } from './dto/password-reset-confirm.dto';
import { PasswordResetRequestDto } from './dto/password-reset-request.dto';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { CurrentUser } from '../../../authorization/interfaces/security/current-user.decorator';
import { Scopes } from '../../../authorization/interfaces/security/scopes.decorator';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { ScopesGuard } from '../../../authorization/interfaces/security/scopes.guard';
import { ThrottleGuard, Throttle } from '../../../common/throttle.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Engagement HTTP controller.
 *
 * Public endpoints:
 *
 *   POST /v1/engagement/email-verification/confirm
 *     — body: { token }. Marks email verified.
 *
 *   POST /v1/engagement/password-reset/request
 *     — body: { email }. Returns 204 always (no enumeration leak).
 *
 *   POST /v1/engagement/password-reset/confirm
 *     — body: { token, newPassword }. Rotates password.
 *
 * Authenticated endpoints (Bearer JWT):
 *
 *   POST /v1/engagement/email-verification/request
 *     — issues a fresh verification token for the calling user.
 *
 *   GET  /v1/engagement/audit-log/me
 *     — returns the calling user's audit log.
 */
@Controller('engagement')
export class EngagementController {
  public constructor(
    private readonly requestEmailVerifUc: RequestEmailVerificationUseCase,
    private readonly confirmEmailVerifUc: ConfirmEmailVerificationUseCase,
    private readonly requestPwResetUc: RequestPasswordResetUseCase,
    private readonly confirmPwResetUc: ConfirmPasswordResetUseCase,
    private readonly getAuditLogUc: GetAuditLogForUserUseCase,
  ) {}

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:read')
  @Post('email-verification/request')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async requestEmailVerif(
    @CurrentUser() principal: UserPrincipal,
  ): Promise<void> {
    await this.requestEmailVerifUc.execute({ userId: principal.userId });
  }

  @Public()
  @Post('email-verification/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmEmailVerif(
    @Body() body: EmailVerificationConfirmDto,
  ): Promise<void> {
    await this.confirmEmailVerifUc.execute({ token: body.token });
  }

  @Public()
  @Throttle(60, 5) // 5 reset requests / minute / IP — prevents email-bombing
  @UseGuards(ThrottleGuard)
  @Post('password-reset/request')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async requestPwReset(
    @Body() body: PasswordResetRequestDto,
  ): Promise<void> {
    await this.requestPwResetUc.execute({ email: body.email });
  }

  @Public()
  @Post('password-reset/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmPwReset(
    @Body() body: PasswordResetConfirmDto,
  ): Promise<void> {
    await this.confirmPwResetUc.execute({
      token: body.token,
      newPassword: body.newPassword,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:read')
  @Get('audit-log/me')
  public async myAuditLog(@CurrentUser() principal: UserPrincipal) {
    return this.getAuditLogUc.execute({ userId: principal.userId, limit: 100 });
  }
}
