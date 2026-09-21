import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ChangePasswordUseCase } from '../../application/use-cases/change-password.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../../application/use-cases/confirm-mfa-enrollment.use-case';
import { DisableMfaUseCase } from '../../application/use-cases/disable-mfa.use-case';
import { EnableMfaUseCase } from '../../application/use-cases/enable-mfa.use-case';
import { RegisterUserUseCase } from '../../application/use-cases/register-user.use-case';
import { UpdateDisplayNameUseCase } from '../../application/use-cases/update-display-name.use-case';
import { VerifySecondFactorUseCase } from '../../application/use-cases/verify-second-factor.use-case';
import { VerifyAppApiKeyUseCase } from '../../../apps/application/use-cases/verify-app-api-key.use-case';
import { ChangePasswordDto } from './dto/change-password.dto';
import { MfaCodeDto } from './dto/mfa-code.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { CurrentUser } from '../../../authorization/interfaces/security/current-user.decorator';
import { Scopes } from '../../../authorization/interfaces/security/scopes.decorator';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { ScopesGuard } from '../../../authorization/interfaces/security/scopes.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Identity bounded-context HTTP controller.
 *
 * Routes:
 *
 *   POST /v1/identity/register — Public. Creates a new user.
 *   PATCH /v1/identity/me — JWT + auth:write. Updates display name.
 *   POST /v1/identity/change-password — JWT + auth:write.
 *   POST /v1/identity/mfa/enable — JWT + auth:write.
 *   POST /v1/identity/mfa/confirm — JWT + auth:write.
 *   POST /v1/identity/mfa/disable — JWT + auth:write.
 *   POST /v1/identity/mfa/verify — JWT + auth:write.
 *
 * V1.5: the `X-User-Id` placeholder header has been replaced with a
 * real Bearer JWT. `JwtAuthGuard` parses `Authorization: Bearer
 * <access_token>`, verifies it via the JWKS, and attaches the
 * `UserPrincipal` to `req.user`. `@CurrentUser()` plucks it out.
 */
@Controller('identity')
export class IdentityController {
  public constructor(
    private readonly registerUserUc: RegisterUserUseCase,
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
    private readonly changePasswordUc: ChangePasswordUseCase,
    private readonly enableMfaUc: EnableMfaUseCase,
    private readonly confirmMfaUc: ConfirmMfaEnrollmentUseCase,
    private readonly disableMfaUc: DisableMfaUseCase,
    private readonly verifySecondFactorUc: VerifySecondFactorUseCase,
    private readonly updateDisplayNameUc: UpdateDisplayNameUseCase,
  ) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  public async register(
    @Body() body: RegisterUserDto,
    @Ip() ip: string,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
    @Headers('user-agent') userAgent?: string,
  ) {
    let appDefaultOrgSlug: string | null = null;
    if (appId && appSecret) {
      const verified = await this.verifyAppApiKeyUc.execute({
        appId: appId.trim(),
        plaintextApiKey: appSecret.trim(),
      });
      appDefaultOrgSlug = verified?.defaultOrgSlug ?? null;
    }
    return this.registerUserUc.execute({
      email: body.email,
      password: body.password,
      organizationSlug: body.organizationSlug,
      appDefaultOrgSlug,
      displayName: body.displayName ?? null,
      ipAddress: ip,
      userAgent: userAgent ?? null,
    });
  }

  /**
   * Self-service profile update. V1 supports only displayName.
   */
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Patch('me')
  @HttpCode(HttpStatus.OK)
  public async updateMe(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: UpdateProfileDto,
  ) {
    if (body.displayName === undefined && body.clearDisplayName !== true) {
      throw new BadRequestException(
        'displayName or clearDisplayName must be provided',
      );
    }
    const displayName =
      body.clearDisplayName === true ? null : (body.displayName ?? null);
    return this.updateDisplayNameUc.execute({
      userId: principal.userId,
      displayName,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async changePassword(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: ChangePasswordDto,
  ): Promise<void> {
    await this.changePasswordUc.execute({
      userId: principal.userId,
      currentPassword: body.currentPassword,
      newPassword: body.newPassword,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('mfa/enable')
  @HttpCode(HttpStatus.OK)
  public async enableMfa(@CurrentUser() principal: UserPrincipal) {
    return this.enableMfaUc.execute({ userId: principal.userId });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('mfa/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: MfaCodeDto,
  ): Promise<void> {
    await this.confirmMfaUc.execute({
      userId: principal.userId,
      code: body.code,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('mfa/disable')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async disableMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: MfaCodeDto,
  ): Promise<void> {
    await this.disableMfaUc.execute({
      userId: principal.userId,
      code: body.code,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('mfa/verify')
  @HttpCode(HttpStatus.OK)
  public async verifyMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: MfaCodeDto,
  ) {
    return this.verifySecondFactorUc.execute({
      userId: principal.userId,
      code: body.code,
    });
  }
}
