import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
} from '@nestjs/common';
import { ChangePasswordUseCase } from '../../application/use-cases/change-password.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../../application/use-cases/confirm-mfa-enrollment.use-case';
import { DisableMfaUseCase } from '../../application/use-cases/disable-mfa.use-case';
import { EnableMfaUseCase } from '../../application/use-cases/enable-mfa.use-case';
import { RegisterUserUseCase } from '../../application/use-cases/register-user.use-case';
import { UpdateDisplayNameUseCase } from '../../application/use-cases/update-display-name.use-case';
import { VerifySecondFactorUseCase } from '../../application/use-cases/verify-second-factor.use-case';
import { ChangePasswordDto } from './dto/change-password.dto';
import { MfaCodeDto } from './dto/mfa-code.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

/**
 * Identity bounded-context HTTP controller.
 *
 * Routes:
 *
 *   POST /v1/identity/register
 *     — Public. Creates a new user under an existing organization (by
 *       email-domain lookup) or under a freshly-created personal org.
 *
 *   POST /v1/identity/change-password
 *     — Authenticated (X-User-Id header for V1; JWT in Phase 12).
 *
 *   POST /v1/identity/mfa/enable
 *     — Authenticated. Returns OTP URL + secret + recovery codes (one-time).
 *
 *   POST /v1/identity/mfa/confirm
 *     — Authenticated. Confirms the first TOTP code, activates MFA.
 *
 *   POST /v1/identity/mfa/disable
 *     — Authenticated. Requires a fresh TOTP code.
 *
 *   POST /v1/identity/mfa/verify
 *     — Internal (Authentication context). Accepts either a TOTP code
 *       or a recovery code, returns which one matched.
 *
 * The constructor parameters are named distinctly from the route handlers
 * to avoid the TS duplicate-identifier issue.
 */
@Controller('identity')
export class IdentityController {
  public constructor(
    private readonly registerUserUc: RegisterUserUseCase,
    private readonly changePasswordUc: ChangePasswordUseCase,
    private readonly enableMfaUc: EnableMfaUseCase,
    private readonly confirmMfaUc: ConfirmMfaEnrollmentUseCase,
    private readonly disableMfaUc: DisableMfaUseCase,
    private readonly verifySecondFactorUc: VerifySecondFactorUseCase,
    private readonly updateDisplayNameUc: UpdateDisplayNameUseCase,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  public async register(@Body() body: RegisterUserDto) {
    return this.registerUserUc.execute({
      email: body.email,
      password: body.password,
      organizationSlug: body.organizationSlug,
      displayName: body.displayName ?? null,
    });
  }

  /**
   * Self-service profile update.
   *
   * V1 supports only displayName. Empty body → 400.
   */
  @Patch('me')
  @HttpCode(HttpStatus.OK)
  public async updateMe(
    @Headers('x-user-id') userId: string,
    @Body() body: UpdateProfileDto,
  ) {
    if (body.displayName === undefined && body.clearDisplayName !== true) {
      throw new BadRequestException(
        'displayName or clearDisplayName must be provided',
      );
    }
    const displayName =
      body.clearDisplayName === true ? null : (body.displayName ?? null);
    return this.updateDisplayNameUc.execute({ userId, displayName });
  }

  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async changePassword(
    @Headers('x-user-id') userId: string,
    @Body() body: ChangePasswordDto,
  ): Promise<void> {
    await this.changePasswordUc.execute({
      userId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
    });
  }

  @Post('mfa/enable')
  @HttpCode(HttpStatus.OK)
  public async enableMfa(@Headers('x-user-id') userId: string) {
    return this.enableMfaUc.execute({ userId });
  }

  @Post('mfa/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmMfa(
    @Headers('x-user-id') userId: string,
    @Body() body: MfaCodeDto,
  ): Promise<void> {
    await this.confirmMfaUc.execute({ userId, code: body.code });
  }

  @Post('mfa/disable')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async disableMfa(
    @Headers('x-user-id') userId: string,
    @Body() body: MfaCodeDto,
  ): Promise<void> {
    await this.disableMfaUc.execute({ userId, code: body.code });
  }

  @Post('mfa/verify')
  @HttpCode(HttpStatus.OK)
  public async verifyMfa(
    @Headers('x-user-id') userId: string,
    @Body() body: MfaCodeDto,
  ) {
    return this.verifySecondFactorUc.execute({ userId, code: body.code });
  }
}
