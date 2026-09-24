/**
 * C-4 — MFA bypass via OAuth password grant.
 *
 * Pins the post-audit contract:
 *   - A user with MFA enabled, who calls LoginUseCase, gets a
 *     session with `mfaVerified = false`.
 *   - Calling the OAuth password grant on that session (which
 *     internally calls RefreshTokenGrantUseCase) fails with
 *     `authorization.token.invalid` BEFORE the audit fix this
 *     would have issued a valid access token — the exact bypass
 *     the audit flagged.
 *   - After VerifySecondFactorUseCase succeeds, the same session
 *     has `mfaVerified = true` and the OAuth grant succeeds.
 *
 * Pure-domain spec (`session.spec.ts`) covers the `markMfaVerified`
 * aggregate behavior. This test pins the integration: that the
 * VerifySecondFactorUseCase → SessionRepository.markMfaVerified
 * → Postgres UPDATE actually flips the flag, AND that the OAuth
 * grant's read path actually checks it.
 */

import { IssueAccessTokenUseCase } from '../src/authorization/application/use-cases/issue-access-token.use-case';
import { RefreshTokenGrantUseCase } from '../src/authorization/application/use-cases/refresh-token-grant.use-case';
import { LoginUseCase } from '../src/authentication/application/use-cases/login.use-case';
import { RegisterUserUseCase } from '../src/identity/application/use-cases/register-user.use-case';
import { VerifySecondFactorUseCase } from '../src/identity/application/use-cases/verify-second-factor.use-case';
import { EnableMfaUseCase } from '../src/identity/application/use-cases/enable-mfa.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../src/identity/application/use-cases/confirm-mfa-enrollment.use-case';
import { authenticator } from 'otplib';
import { buildIntegrationContext, teardown, uniqueEmail } from './harness';

describe('C-4 — MFA bypass via OAuth password grant (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let loginUc: LoginUseCase;
  let registerUc: RegisterUserUseCase;
  let enableUc: EnableMfaUseCase;
  let confirmUc: ConfirmMfaEnrollmentUseCase;
  let verifyUc: VerifySecondFactorUseCase;
  let grantUc: RefreshTokenGrantUseCase;
  let issueUc: IssueAccessTokenUseCase;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    loginUc = ctx.get(LoginUseCase);
    registerUc = ctx.get(RegisterUserUseCase);
    enableUc = ctx.get(EnableMfaUseCase);
    confirmUc = ctx.get(ConfirmMfaEnrollmentUseCase);
    verifyUc = ctx.get(VerifySecondFactorUseCase);
    grantUc = ctx.get(RefreshTokenGrantUseCase);
    issueUc = ctx.get(IssueAccessTokenUseCase);
  });

  afterAll(async () => {
    await ctx.close();
    await teardown();
  });

  it('OAuth grant refuses pre-MFA session, accepts post-MFA session', async () => {
    // 1. Register a fresh user.
    const email = uniqueEmail('c4');
    const password = 'correct horse battery staple 1!';
    await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });
    const login = await loginUc.execute({
      email,
      password,
      appDefaultOrgSlug: null,
    });
    const userId = login.userId;
    expect(login.mfaRequired).toBe(false);

    // 2. Enable MFA, get the secret.
    const enableResult = await enableUc.execute({ userId });
    const secret = enableResult.secret;

    // 3. Confirm MFA on the user's record.
    const code1 = authenticator.generate(secret);
    await confirmUc.execute({ userId, code: code1 });

    // 4. Re-login → MFA is now CONFIRMED, so the session has
    //    mfaVerified=false (must call verify on this session).
    const login2 = await loginUc.execute({
      email,
      password,
      appDefaultOrgSlug: null,
    });
    const sessionId = login2.sessionId;
    const refreshToken = login2.refreshToken;
    expect(login2.mfaRequired).toBe(true);
    void sessionId; // kept for clarity; not used here

    // 5. THE ATTACK: try the OAuth grant on the pre-MFA session.
    //    Pre-audit-fix this would have issued a valid access token.
    //    Post-fix it must throw.
    // The grant hashes the refresh token internally, so we pass
    // the plaintext directly — not the pre-hashed value.
    await expect(
      grantUc.execute({
        refreshToken,
        organizationSlug: null,
      }),
    ).rejects.toMatchObject({
      code: 'authorization.token.invalid',
    });

    // 6. Verify MFA on the session — flips mfaVerified=true.
    const code2 = authenticator.generate(secret);
    await verifyUc.execute({
      userId,
      sessionId,
      code: code2,
    });

    // 8. The same refresh token now succeeds — the OAuth grant
    //    sees mfaVerified=true and mints an access token.
    const issued = await grantUc.execute({
      refreshToken,
      organizationSlug: null,
    });
    expect(issued.accessToken).toBeTruthy();
    expect(issued.accessToken.length).toBeGreaterThan(20);

    // IssueAccessTokenUseCase sanity check — we can re-issue too.
    const ref = await issueUc.execute({
      userId,
      organizationSlug: null,
    });
    expect(ref.accessToken).toBeTruthy();
  }, 60000);
});
