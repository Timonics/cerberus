import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Patch,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ChangePasswordUseCase } from '../../application/use-cases/change-password.use-case';
import { CreateOwnOrganizationUseCase } from '../../application/use-cases/create-own-organization.use-case';
import {
  CompleteMfaVerificationUseCase,
  MfaLockedError,
} from '../../application/use-cases/complete-mfa-verification.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../../application/use-cases/confirm-mfa-enrollment.use-case';
import { DisableMfaUseCase } from '../../application/use-cases/disable-mfa.use-case';
import { EnableMfaUseCase } from '../../application/use-cases/enable-mfa.use-case';
import { GetUserUseCase } from '../../application/use-cases/get-user.use-case';
import { RegisterUserUseCase } from '../../application/use-cases/register-user.use-case';
import { UpdateDisplayNameUseCase } from '../../application/use-cases/update-display-name.use-case';
import { VerifyAppApiKeyUseCase } from '../../../apps/application/use-cases/verify-app-api-key.use-case';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateOwnOrganizationDto } from './dto/create-own-organization.dto';
import { EnableMfaDto } from './dto/enable-mfa.dto';
import { MfaCodeDto } from './dto/mfa-code.dto';
import { ConfirmMfaDto } from './dto/confirm-mfa.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { CurrentUser } from '../../../authorization/interfaces/security/current-user.decorator';
import { Scopes } from '../../../authorization/interfaces/security/scopes.decorator';
import { JwtAuthGuard } from '../../../authorization/interfaces/security/jwt-auth.guard';
import { ScopesGuard } from '../../../authorization/interfaces/security/scopes.guard';
import { MfaVerifyGuard } from '../security/mfa-verify.guard';
import { ThrottleGuard, Throttle } from '../../../common/throttle.guard';
import { UserPrincipal } from '../../../authorization/domain/value-objects/user-principal';

/**
 * Identity bounded-context HTTP controller.
 *
 * Routes:
 *
 *   POST /v1/identity/register — Public. Creates a new user.
 *     Returns 201 with an opaque body whether the user was created or
 *     the email already exists (no account-enumeration oracle).
 *   PATCH /v1/identity/me — JWT + auth:write. Updates display name.
 *   GET /v1/identity/me — JWT + auth:read. Returns the caller's profile
 *     (email, displayName, org, role, MFA status).
 *   POST /v1/identity/orgs — JWT + auth:write. Creates a new org, makes
 *     the caller OWNER, and moves the caller's account into it.
 *   POST /v1/identity/change-password — JWT + auth:write.
 *   POST /v1/identity/mfa/enable — JWT + auth:write + currentPassword.
 *   POST /v1/identity/mfa/confirm — JWT + auth:write.
 *   POST /v1/identity/mfa/disable — JWT + auth:write.
 *   POST /v1/identity/mfa/verify — JWT (auth:write OR mfa:verify scope)
 *     + throttle + failure lockout. Completes an MFA-pending login and
 *     returns the real token pair.
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
    private readonly completeMfaVerificationUc: CompleteMfaVerificationUseCase,
    private readonly updateDisplayNameUc: UpdateDisplayNameUseCase,
    private readonly getUserUc: GetUserUseCase,
    private readonly createOwnOrganizationUc: CreateOwnOrganizationUseCase,
  ) {}

  @Public()
  @Throttle(60, 10) // 10 registrations / minute / IP
  @UseGuards(ThrottleGuard)
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  public async register(
    @Body() body: RegisterUserDto,
    @Ip() ip: string,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
    @Headers('user-agent') userAgent?: string,
  ) {
    // 2026-10-19 audit LOW (partial app credentials): exactly one of
    // the two headers present is ambiguous — silently ignoring it used
    // to bind the user to the WRONG org. Fail closed instead.
    if ((appId && !appSecret) || (!appId && appSecret)) {
      throw new BadRequestException({
        code: 'identity.app_credentials.incomplete',
        message:
          'X-Cerberus-App-Id and X-Cerberus-App-Secret must be sent together',
      });
    }

    let appDefaultOrgSlug: string | null = null;
    if (appId && appSecret) {
      // 2026-10-19 audit LOW (app-id enumeration): map EVERY app-
      // credential failure — unknown app, revoked app, wrong secret —
      // to one uniform 401. The verify use-case may throw distinct
      // codes for internal auditing; they must not reach the client.
      try {
        const verified = await this.verifyAppApiKeyUc.execute({
          appId: appId.trim(),
          plaintextApiKey: appSecret.trim(),
        });
        appDefaultOrgSlug = verified?.defaultOrgSlug ?? null;
      } catch {
        throw new UnauthorizedException({
          code: 'app.credentials.invalid',
          message: 'App credentials are invalid',
        });
      }
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
   * Self-service profile read.
   */
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:read')
  @Get('me')
  @HttpCode(HttpStatus.OK)
  public async getMe(@CurrentUser() principal: UserPrincipal) {
    return this.getUserUc.execute({ userId: principal.userId });
  }

  /**
   * Self-service organization creation. The caller becomes OWNER of the
   * new org and their account moves into it (V1 is single-org-per-user;
   * they leave their previous org, typically the auto-created personal
   * one). Colleagues can then register with `organizationSlug=<slug>`.
   *
   *   201 → { id, slug, name }
   *   409 → slug already taken
   */
  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('orgs')
  @HttpCode(HttpStatus.CREATED)
  public async createOwnOrganization(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: CreateOwnOrganizationDto,
  ) {
    const result = await this.createOwnOrganizationUc.execute({
      slug: body.slug,
      name: body.name,
      description: body.description ?? null,
      callerUserId: principal.userId,
    });
    return {
      id: result.organization.id.value,
      slug: result.organization.slug.value,
      name: result.organization.name,
    };
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
  public async enableMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: EnableMfaDto,
  ) {
    // 2026-10-19 audit MEDIUM (enrollment fresh-auth): requires the
    // current password — a stolen bearer token alone can no longer
    // enable MFA (and lock the real user out).
    return this.enableMfaUc.execute({
      userId: principal.userId,
      currentPassword: body.currentPassword,
    });
  }

  @UseGuards(JwtAuthGuard, ScopesGuard)
  @Scopes('auth:write')
  @Post('mfa/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async confirmMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: ConfirmMfaDto,
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
    @Body() body: ConfirmMfaDto,
  ): Promise<void> {
    await this.disableMfaUc.execute({
      userId: principal.userId,
      code: body.code,
    });
  }

  /**
   * Complete MFA verification for a pending login (2026-10-19 fixes
   * C1 + H-5b).
   *
   * Auth: accepts EITHER a normal access JWT (scope `auth:write`) OR
   * the `mfa:verify`-scoped pending token issued by login when MFA is
   * outstanding (see `MfaVerifyGuard`).
   *
   * Controls: 5 requests/minute/IP (throttle) AND a per-(user,
   * session) failure counter — 5 bad codes locks the pair for 15
   * minutes. Both success and failure are audited.
   *
   * Response: 200 `{ accessToken, refreshToken, mfaVerified: true }`.
   */
  @Throttle(60, 5) // 5 verifications / minute / IP (H-5b)
  @UseGuards(MfaVerifyGuard, ThrottleGuard)
  @Post('mfa/verify')
  @HttpCode(HttpStatus.OK)
  public async verifyMfa(
    @CurrentUser() principal: UserPrincipal,
    @Body() body: MfaCodeDto,
  ) {
    try {
      return await this.completeMfaVerificationUc.execute({
        userId: principal.userId,
        sessionId: body.sessionId,
        code: body.code,
      });
    } catch (err) {
      if (err instanceof MfaLockedError) {
        // 401 (not 429): the caller holds valid credentials but the
        // second-factor pair is temporarily locked.
        throw new UnauthorizedException({
          code: 'identity.mfa.locked',
          message: err.message,
        });
      }
      throw err;
    }
  }
}
