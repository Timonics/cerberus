import { Inject } from '@nestjs/common';
import { Args, ID, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthGuard } from '../../../graphql/guards/auth-guard.decorator';
import { CurrentUser } from '../../../graphql/graphql-context';
import { GqlBadRequestException } from '../../../graphql/graphql-errors';
import { RegisterUserUseCase } from '../../application/use-cases/register-user.use-case';
import { ChangePasswordUseCase } from '../../application/use-cases/change-password.use-case';
import { UpdateDisplayNameUseCase } from '../../application/use-cases/update-display-name.use-case';
import { EnableMfaUseCase } from '../../application/use-cases/enable-mfa.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../../application/use-cases/confirm-mfa-enrollment.use-case';
import { ListSessionsUseCase } from '../../../authentication/application/use-cases/list-sessions.use-case';
import { RevokeSessionUseCase } from '../../../authentication/application/use-cases/revoke-session.use-case';
import { DisableMfaUseCase } from '../../application/use-cases/disable-mfa.use-case';
import { VerifySecondFactorUseCase } from '../../application/use-cases/verify-second-factor.use-case';
import { GetUserUseCase } from '../../application/use-cases/get-user.use-case';
import {
  RegisterInput,
  ChangePasswordInput,
  UpdateDisplayNameInput,
  MfaCodeInput,
  VerifyMfaInput,
} from '../../../graphql/models/inputs';

/**
 * Identity GraphQL resolver.
 *
 * Mirrors the REST `IdentityController`. Every method delegates to
 * the same use-cases the REST endpoints call.
 *
 * Auth: all methods except `register` and `health` require a valid
 * bearer token (decorated with `@AuthGuard()`).
 */
@Resolver()
export class IdentityResolver {
  public constructor(
    @Inject(RegisterUserUseCase)
    private readonly registerUserUc: RegisterUserUseCase,
    @Inject(ChangePasswordUseCase)
    private readonly changePasswordUc: ChangePasswordUseCase,
    @Inject(UpdateDisplayNameUseCase)
    private readonly updateDisplayNameUc: UpdateDisplayNameUseCase,
    @Inject(EnableMfaUseCase) private readonly enableMfaUc: EnableMfaUseCase,
    @Inject(ConfirmMfaEnrollmentUseCase)
    private readonly confirmMfaUc: ConfirmMfaEnrollmentUseCase,
    @Inject(DisableMfaUseCase) private readonly disableMfaUc: DisableMfaUseCase,
    @Inject(VerifySecondFactorUseCase)
    private readonly verify2faUc: VerifySecondFactorUseCase,
    @Inject(GetUserUseCase) private readonly getUserUc: GetUserUseCase,
    @Inject(ListSessionsUseCase)
    private readonly listSessionsUc: ListSessionsUseCase,
    @Inject(RevokeSessionUseCase)
    private readonly revokeSessionUc: RevokeSessionUseCase,
  ) {}

  @Query(() => Boolean, { description: 'Unauthenticated liveness probe.' })
  public health(): boolean {
    return true;
  }

  @AuthGuard()
  @Query(() => 'User', {
    description:
      'The currently-authenticated user. Returns the User aggregate, including organization and MFA status.',
  })
  public async me(@CurrentUser() user: { sub: string }) {
    const u = await this.getUserUc.execute({ userId: user.sub });
    return {
      id: u.userId,
      email: u.email,
      displayName: u.displayName,
      emailVerifiedAt: null, // not returned by GetUserUseCase today; add in V1.5
      createdAt: u.createdAt,
      mfaEnabled: u.mfaEnabled,
      role: u.role,
      organization: {
        id: u.organizationId,
        slug: '', // not returned by GetUserUseCase today; add in V1.5
        name: '',
      },
    };
  }

  @AuthGuard({ requireOrgAdmin: true })
  @Query(() => 'User', {
    nullable: true,
    description:
      'Look up any user by ID. Requires org:admin scope (OWNER or ADMIN role).',
  })
  public async getUser(@Args('id') id: string) {
    try {
      const u = await this.getUserUc.execute({ userId: id });
      return {
        id: u.userId,
        email: u.email,
        displayName: u.displayName,
        emailVerifiedAt: null,
        createdAt: u.createdAt,
        mfaEnabled: u.mfaEnabled,
        role: u.role,
        organization: {
          id: u.organizationId,
          slug: '',
          name: '',
        },
      };
    } catch {
      return null;
    }
  }

  @Mutation(() => 'RegisterPayload', {
    description:
      'Register a new user. Open to unauthenticated callers. Auto-creates a personal organization when no slug is supplied and no email-domain matches.',
  })
  public async register(@Args('input') input: RegisterInput) {
    const result = await this.registerUserUc.execute({
      email: input.email,
      password: input.password,
      organizationSlug: input.organizationSlug ?? undefined,
      displayName: input.displayName ?? undefined,
    });
    return {
      userId: result.userId,
      email: result.email,
      organizationId: result.organizationId,
      organizationSlug: result.organizationSlug,
      autoCreatedOrg: result.autoCreatedOrg,
    };
  }

  @AuthGuard()
  @Mutation(() => Boolean, {
    description:
      "Change the authenticated user's password. Emits identity.password.changed; all the user's live sessions are revoked.",
  })
  public async changePassword(
    @CurrentUser() user: { sub: string },
    @Args('input') input: ChangePasswordInput,
  ): Promise<boolean> {
    await this.changePasswordUc.execute({
      userId: user.sub,
      currentPassword: input.currentPassword,
      newPassword: input.newPassword,
    });
    return true;
  }

  @AuthGuard()
  @Mutation(() => 'User', {
    description:
      "Update the authenticated user's display name. Pass `clearDisplayName: true` to remove it.",
  })
  public async updateDisplayName(
    @CurrentUser() user: { sub: string },
    @Args('input') input: UpdateDisplayNameInput,
  ) {
    if (input.displayName === undefined && input.clearDisplayName !== true) {
      throw new GqlBadRequestException(
        'displayName or clearDisplayName must be provided',
      );
    }
    const newName = input.clearDisplayName ? null : (input.displayName ?? null);
    await this.updateDisplayNameUc.execute({
      userId: user.sub,
      displayName: newName,
    });
    const u = await this.getUserUc.execute({ userId: user.sub });
    return {
      id: u.userId,
      email: u.email,
      displayName: u.displayName,
      emailVerifiedAt: null,
      createdAt: u.createdAt,
      mfaEnabled: u.mfaEnabled,
      role: u.role,
      organization: { id: u.organizationId, slug: '', name: '' },
    };
  }

  @AuthGuard()
  @Mutation(() => 'MfaEnrollment', {
    description:
      'Begin MFA enrollment. Returns the TOTP secret and 10 recovery codes (each returned ONCE).',
  })
  public async enableMfa(@CurrentUser() user: { sub: string }) {
    const result = await this.enableMfaUc.execute({ userId: user.sub });
    return {
      secret: result.secret,
      otpauthUrl: result.otpAuthUrl,
      recoveryCodes: result.recoveryCodes,
    };
  }

  @AuthGuard()
  @Mutation(() => Boolean, {
    description: 'Confirm MFA enrollment with a 6-digit TOTP code.',
  })
  public async confirmMfaEnrollment(
    @CurrentUser() user: { sub: string },
    @Args('input') input: MfaCodeInput,
  ): Promise<boolean> {
    await this.confirmMfaUc.execute({
      userId: user.sub,
      code: input.code,
    });
    return true;
  }

  @AuthGuard()
  @Mutation(() => Boolean, {
    description:
      'Disable MFA entirely. Requires a valid TOTP code (prevents unauthorized disable).',
  })
  public async disableMfa(
    @CurrentUser() user: { sub: string },
    @Args('input') input: MfaCodeInput,
  ): Promise<boolean> {
    await this.disableMfaUc.execute({
      userId: user.sub,
      code: input.code,
    });
    return true;
  }

  @AuthGuard()
  @Mutation(() => 'VerifyMfaResult', {
    description:
      'Verify a TOTP code or 10-character recovery code. Returns which type matched.',
  })
  public async verifyMfa(
    @CurrentUser() user: { sub: string },
    @Args('input') input: VerifyMfaInput,
  ) {
    const matched = await this.verify2faUc.execute({
      userId: user.sub,
      sessionId: input.sessionId,
      code: input.code,
    });
    return { matched };
  }

  // ---------------------------------------------------------------------------
  // Sessions (V1.5)
  // ---------------------------------------------------------------------------

  @AuthGuard()
  @Query(() => '[Session!]!', {
    description: "List the calling user's active sessions.",
  })
  public async sessions(
    @CurrentUser() user: { sub: string },
  ): Promise<unknown[]> {
    const result = await this.listSessionsUc.execute({ userId: user.sub });
    return result.sessions.map((s) => ({
      id: s.sessionId,
      deviceLabel: s.deviceLabel,
      ipAddress: s.ipAddress,
      issuedAt: s.issuedAt.toISOString(),
      expiresAt: s.expiresAt.toISOString(),
      lastUsedAt: s.lastUsedAt ? s.lastUsedAt.toISOString() : null,
    }));
  }

  @AuthGuard()
  @Mutation(() => 'Boolean', {
    description:
      'Revoke a specific session by ID. Cross-user revoke is rejected.',
  })
  public async revokeSession(
    @CurrentUser() user: { sub: string },
    @Args('sessionId', { type: () => ID }) sessionId: string,
  ): Promise<boolean> {
    await this.revokeSessionUc.execute({
      sessionId,
      requesterUserId: user.sub,
    });
    return true;
  }
}
