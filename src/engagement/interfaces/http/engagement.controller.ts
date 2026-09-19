import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { ConfirmEmailVerificationUseCase } from '../../application/use-cases/confirm-email-verification.use-case';
import { ConfirmPasswordResetUseCase } from '../../application/use-cases/confirm-password-reset.use-case';
import { GetAuditLogForUserUseCase } from '../../application/use-cases/get-audit-log-for-user.use-case';
import { RequestEmailVerificationUseCase } from '../../application/use-cases/request-email-verification.use-case';
import { RequestPasswordResetUseCase } from '../../application/use-cases/request-password-reset.use-case';
import { EmailVerificationConfirmDto } from './dto/email-verification-confirm.dto';
import { PasswordResetConfirmDto } from './dto/password-reset-confirm.dto';
import { PasswordResetRequestDto } from './dto/password-reset-request.dto';

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
 * Authenticated endpoints (X-User-Id header for V1):
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

  @Post('email-verification/request')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async requestEmailVerif(
    @Headers('x-user-id') userId: string,
  ): Promise<void> {
    await this.requestEmailVerifUc.execute({ userId });
  }

  @Post('email-verification/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmEmailVerif(
    @Body() body: EmailVerificationConfirmDto,
  ): Promise<void> {
    await this.confirmEmailVerifUc.execute({ token: body.token });
  }

  @Post('password-reset/request')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async requestPwReset(
    @Body() body: PasswordResetRequestDto,
  ): Promise<void> {
    await this.requestPwResetUc.execute({ email: body.email });
  }

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

  @Get('audit-log/me')
  public async myAuditLog(@Headers('x-user-id') userId: string) {
    return this.getAuditLogUc.execute({ userId, limit: 100 });
  }
}
