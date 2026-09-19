import { Inject } from '@nestjs/common';
import { Args, Int, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthGuard } from '../../../graphql/guards/auth-guard.decorator';
import {
  CurrentUser,
  IpAddress,
  UserAgent,
} from '../../../graphql/graphql-context';
import { ConfirmEmailVerificationUseCase } from '../../application/use-cases/confirm-email-verification.use-case';
import { GetAuditLogForUserUseCase } from '../../application/use-cases/get-audit-log-for-user.use-case';
import { RequestEmailVerificationUseCase } from '../../application/use-cases/request-email-verification.use-case';
import { RequestPasswordResetUseCase } from '../../application/use-cases/request-password-reset.use-case';
import { ConfirmPasswordResetUseCase } from '../../application/use-cases/confirm-password-reset.use-case';
import {
  ConfirmEmailVerificationInput,
  ConfirmPasswordResetInput,
  RequestPasswordResetInput,
} from '../../../graphql/models/inputs';

/**
 * Engagement GraphQL resolver.
 *
 * Mirrors the REST `EngagementController`. All routes delegate to the
 * same use-cases.
 */
@Resolver()
export class EngagementResolver {
  public constructor(
    @Inject(RequestEmailVerificationUseCase)
    private readonly requestEmailVerifUc: RequestEmailVerificationUseCase,
    @Inject(ConfirmEmailVerificationUseCase)
    private readonly confirmEmailVerifUc: ConfirmEmailVerificationUseCase,
    @Inject(RequestPasswordResetUseCase)
    private readonly requestPwResetUc: RequestPasswordResetUseCase,
    @Inject(ConfirmPasswordResetUseCase)
    private readonly confirmPwResetUc: ConfirmPasswordResetUseCase,
    @Inject(GetAuditLogForUserUseCase)
    private readonly getAuditLogUc: GetAuditLogForUserUseCase,
  ) {}

  @AuthGuard()
  @Mutation(() => Boolean, {
    description:
      'Request a fresh email-verification token. Always returns true. The plaintext token is sent via the configured mail sender — not exposed here.',
  })
  public async requestEmailVerification(
    @CurrentUser() user: { sub: string },
  ): Promise<boolean> {
    await this.requestEmailVerifUc.execute({ userId: user.sub });
    return true;
  }

  @Mutation(() => Boolean, {
    description:
      'Redeem an email-verification token. Sets User.emailVerifiedAt. Token is single-use; expires after 24 hours.',
  })
  public async confirmEmailVerification(
    @Args('input') input: ConfirmEmailVerificationInput,
  ): Promise<boolean> {
    await this.confirmEmailVerifUc.execute({ token: input.token });
    return true;
  }

  @Mutation(() => Boolean, {
    description:
      'Request a password-reset token. Open to unauthenticated callers. Always returns true (no account enumeration).',
  })
  public async requestPasswordReset(
    @Args('input') input: RequestPasswordResetInput,
  ): Promise<boolean> {
    await this.requestPwResetUc.execute({ email: input.email });
    return true;
  }

  @Mutation(() => Boolean, {
    description:
      "Redeem a password-reset token and set a new password. On success, all the user's live sessions are revoked.",
  })
  public async confirmPasswordReset(
    @Args('input') input: ConfirmPasswordResetInput,
  ): Promise<boolean> {
    await this.confirmPwResetUc.execute({
      token: input.token,
      newPassword: input.newPassword,
    });
    return true;
  }

  @AuthGuard()
  @Query(() => 'AuditLogPage', {
    description:
      "The authenticated user's own audit log, most recent first. Limit is bounded server-side to 1–500.",
  })
  public async myAuditLog(
    @CurrentUser() user: { sub: string },
    @Args('limit', { type: () => Int, defaultValue: 100 }) limit: number,
    @IpAddress() ipAddress: string | undefined,
    @UserAgent() userAgent: string | undefined,
  ) {
    const boundedLimit = Math.min(Math.max(limit, 1), 500);
    const result = await this.getAuditLogUc.execute({
      userId: user.sub,
      limit: boundedLimit,
    });
    return {
      entries: result.entries,
      total: result.entries.length,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    };
  }
}
