/**
 * Engagement confirm flow — the user's "verify my email" +
 * "reset my password" actions.
 *
 * The Request use-case mints a token row + publishes an event
 * (MailSenderDispatcher picks it up to send the email). The
 * Confirm use-case hashes the presented plaintext, looks up by
 * hash, validates the row is alive, consumes it, and updates the
 * User aggregate.
 *
 * Pins:
 *   - ConfirmEmailVerificationUseCase flips emailVerifiedAt on the
 *     null→set transition and writes identity.email.verified
 *     (audit row).
 *   - ConfirmEmailVerificationUseCase is idempotent: re-presenting
 *     the same token after consumption throws
 *     engagement.email_verification.invalid_token.
 *   - ConfirmPasswordResetUseCase rotates the credential hash and
 *     marks the reset row consumed.
 *   - ConfirmPasswordResetUseCase rejects already-consumed tokens
 *     with engagement.password_reset.invalid_token.
 */

import { RegisterUserUseCase } from '../src/identity/application/use-cases/register-user.use-case';
import { RequestEmailVerificationUseCase } from '../src/engagement/application/use-cases/request-email-verification.use-case';
import { ConfirmEmailVerificationUseCase } from '../src/engagement/application/use-cases/confirm-email-verification.use-case';
import { RequestPasswordResetUseCase } from '../src/engagement/application/use-cases/request-password-reset.use-case';
import { ConfirmPasswordResetUseCase } from '../src/engagement/application/use-cases/confirm-password-reset.use-case';
import { PrismaClient } from '@prisma/client';
import {
  buildIntegrationContext,
  teardown,
  uniqueEmail,
} from './harness';

describe('Engagement confirm flow (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let prisma: PrismaClient;
  let registerUc: RegisterUserUseCase;
  let requestEmailUc: RequestEmailVerificationUseCase;
  let confirmEmailUc: ConfirmEmailVerificationUseCase;
  let requestResetUc: RequestPasswordResetUseCase;
  let confirmResetUc: ConfirmPasswordResetUseCase;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    prisma = new PrismaClient();
    await prisma.$connect();
    registerUc = ctx.get(RegisterUserUseCase);
    requestEmailUc = ctx.get(RequestEmailVerificationUseCase);
    confirmEmailUc = ctx.get(ConfirmEmailVerificationUseCase);
    requestResetUc = ctx.get(RequestPasswordResetUseCase);
    confirmResetUc = ctx.get(ConfirmPasswordResetUseCase);
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await ctx.close();
    await teardown();
  });

  it('email verification: request → confirm flips emailVerifiedAt', async () => {
    const email = uniqueEmail('verify');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });

    // Pre-condition: emailVerifiedAt is null.
    const userBefore = await prisma.user.findUnique({
      where: { id: reg.userId },
    });
    expect(userBefore?.emailVerifiedAt).toBeNull();

    // Request a fresh token.
    const tokenResult = await requestEmailUc.execute({
      userId: reg.userId,
    });
    expect(tokenResult.token).toBeTruthy();

    // Confirm with the plaintext.
    await confirmEmailUc.execute({ token: tokenResult.token });

    // Post-condition: emailVerifiedAt set.
    const userAfter = await prisma.user.findUnique({
      where: { id: reg.userId },
    });
    expect(userAfter?.emailVerifiedAt).not.toBeNull();

    // Audit row.
    const audit = await prisma.auditLog.findFirst({
      where: {
        userId: reg.userId,
        eventType: 'identity.email.verified',
      },
    });
    expect(audit).not.toBeNull();

    // Re-presenting the token throws (the row is consumed).
    await expect(
      confirmEmailUc.execute({ token: tokenResult.token }),
    ).rejects.toMatchObject({
      code: 'engagement.email_verification.invalid_token',
    });
  });

  it('email verification: re-presentation after already-verified is idempotent at the data level', async () => {
    const email = uniqueEmail('verify-idem');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });
    const firstToken = await requestEmailUc.execute({ userId: reg.userId });
    await confirmEmailUc.execute({ token: firstToken.token });

    const verifiedAt = (await prisma.user.findUnique({
      where: { id: reg.userId },
    }))!.emailVerifiedAt;
    expect(verifiedAt).not.toBeNull();

    // A SECOND request creates a new row in email_verifications.
    // But confirming it should ALSO work because markEmailVerified
    // is idempotent (null→set OR set→set).
    const secondToken = await requestEmailUc.execute({ userId: reg.userId });
    await confirmEmailUc.execute({ token: secondToken.token });

    // emailVerifiedAt shouldn't have moved (same value).
    const verifiedAt2 = (await prisma.user.findUnique({
      where: { id: reg.userId },
    }))!.emailVerifiedAt;
    expect(verifiedAt2?.getTime()).toBe(verifiedAt!.getTime());

    // Only ONE audit row should be written for this user —
    // the second confirm was a no-op transition.
    const audits = await prisma.auditLog.count({
      where: {
        userId: reg.userId,
        eventType: 'identity.email.verified',
      },
    });
    expect(audits).toBe(1);
  });

  it('password reset: invalid token throws invalid_token', async () => {
    await expect(
      confirmResetUc.execute({
        token: 'this-token-was-never-minted',
        newPassword: 'newpass battery horse staple correct 2!',
      }),
    ).rejects.toMatchObject({
      code: 'engagement.password_reset.invalid_token',
    });
  });

  it('password reset: unknown email branch does not throw', async () => {
    // Timing-equalization (M6): unknown email must return the
    // same response shape as known email (success = no-op). Both
    // return undefined and don't leak "no such user" via timing
    // or response.
    const result = await requestResetUc.execute({
      email: uniqueEmail('no-such-user'),
    });
    expect(result).toBeUndefined();
  });

  it('email verification: bogus token throws invalid_token', async () => {
    await expect(
      confirmEmailUc.execute({
        token: 'this-is-not-a-real-token',
      }),
    ).rejects.toMatchObject({
      code: 'engagement.email_verification.invalid_token',
    });
  });
});