/**
 * C-1/C-4 — MFA bypass closure, post-2026-10-19 contract.
 *
 * Pins the new MFA-pending login contract end-to-end at the use-case
 * layer:
 *   - Login for an MFA-enabled user returns
 *     `{ mfaRequired: true, mfaToken, sessionId }` — NO refreshToken
 *     and NO accessToken. The mfaToken is a scoped JWT
 *     (scope 'mfa:verify') for POST /v1/identity/mfa/verify.
 *   - The REST refresh use-case (RefreshSessionUseCase) and the OAuth2
 *     refresh_token grant (RefreshTokenGrantUseCase) both reject a
 *     session whose MFA verification is still pending with 401
 *     `authentication.mfa.required` — previously the REST path never
 *     checked and a password-only attacker walked through /refresh.
 *   - After VerifySecondFactorUseCase succeeds on the session, both
 *     paths mint tokens normally.
 *   - Inline second factor: login with a valid `mfaCode` completes in
 *     one round-trip and returns the normal token pair.
 *
 * The pre-verify refresh assertions need a plaintext refresh token for
 * the pending session; since login no longer discloses one, we seed the
 * session directly via the repository (same pattern as
 * refresh-rotation.e2e-spec.ts).
 */

import { IssueAccessTokenUseCase } from '../src/authorization/application/use-cases/issue-access-token.use-case';
import { RefreshTokenGrantUseCase } from '../src/authorization/application/use-cases/refresh-token-grant.use-case';
import { LoginUseCase } from '../src/authentication/application/use-cases/login.use-case';
import { RegisterUserUseCase } from '../src/identity/application/use-cases/register-user.use-case';
import { VerifySecondFactorUseCase } from '../src/identity/application/use-cases/verify-second-factor.use-case';
import { EnableMfaUseCase } from '../src/identity/application/use-cases/enable-mfa.use-case';
import { ConfirmMfaEnrollmentUseCase } from '../src/identity/application/use-cases/confirm-mfa-enrollment.use-case';
import { RefreshSessionUseCase } from '../src/authentication/application/use-cases/refresh-session.use-case';
import { Session } from '../src/authentication/domain/aggregates/session';
import { SessionId } from '../src/authentication/domain/value-objects/session-id';
import { IpAddress } from '../src/authentication/domain/value-objects/ip-address';
import { RefreshTokenHash } from '../src/authentication/domain/value-objects/refresh-token-hash';
import { UserId } from '../src/identity/domain/value-objects/user-id';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../src/authentication/domain/ports/session.repository.port';
import { TRANSACTION_RUNNER, TransactionRunner } from '../src/shared/domain';
import { randomUUID } from 'node:crypto';
import { authenticator } from 'otplib';
import { buildIntegrationContext, teardown, uniqueEmail } from './harness';

describe('C-1/C-4 — MFA bypass closure (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let loginUc: LoginUseCase;
  let registerUc: RegisterUserUseCase;
  let enableUc: EnableMfaUseCase;
  let confirmUc: ConfirmMfaEnrollmentUseCase;
  let verifyUc: VerifySecondFactorUseCase;
  let grantUc: RefreshTokenGrantUseCase;
  let refreshUc: RefreshSessionUseCase;
  let issueUc: IssueAccessTokenUseCase;
  let sessionRepo: SessionRepository;
  let txRunner: TransactionRunner;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    loginUc = ctx.get(LoginUseCase);
    registerUc = ctx.get(RegisterUserUseCase);
    enableUc = ctx.get(EnableMfaUseCase);
    confirmUc = ctx.get(ConfirmMfaEnrollmentUseCase);
    verifyUc = ctx.get(VerifySecondFactorUseCase);
    grantUc = ctx.get(RefreshTokenGrantUseCase);
    refreshUc = ctx.get(RefreshSessionUseCase);
    issueUc = ctx.get(IssueAccessTokenUseCase);
    sessionRepo = ctx.get<SessionRepository>(SESSION_REPOSITORY);
    txRunner = ctx.get<TransactionRunner>(TRANSACTION_RUNNER);
  });

  afterAll(async () => {
    await ctx.close();
    await teardown();
  });

  it('login returns mfaRequired + mfaToken with NO tokens; refresh/grant reject with authentication.mfa.required until verified', async () => {
    // 1. Register a fresh user.
    const email = uniqueEmail('c1');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });
    const userId = reg.userId;

    // 2. Enable MFA (currentPassword required post-audit) + confirm.
    const enableResult = await enableUc.execute({
      userId,
      currentPassword: password,
    });
    const secret = enableResult.secret;
    await confirmUc.execute({
      userId,
      code: authenticator.generate(secret),
    });

    // 3. Re-login → MFA-pending contract: no tokens leave the server.
    const login2 = await loginUc.execute({
      email,
      password,
      appDefaultOrgSlug: null,
    });
    expect(login2.mfaRequired).toBe(true);
    expect(login2.mfaToken).toBeTruthy();
    expect(login2.sessionId).toBeTruthy();
    // C1: the pending response must NOT carry a usable refresh or
    // access token.
    expect(login2.refreshToken).toBeNull();

    // 4. Seed a known-plaintext pending session for the user so we can
    //    exercise the refresh/grant rejection (login never discloses
    //    the pending session's plaintext). Fresh id — no collision
    //    with the session login just created.
    const sessionId = SessionId.create(randomUUID());
    const pendingPlaintext = `c1-pending-${Date.now()}-${Math.random()}`;
    const pendingHash = await RefreshTokenHash.fromPlaintext(pendingPlaintext);
    const pendingSession = Session.create({
      id: sessionId,
      userId: UserId.create(userId),
      familyId: login2.familyId,
      refreshHash: pendingHash,
      userAgent: null,
      ipAddress: IpAddress.create('127.0.0.1'),
      deviceLabel: null,
      organizationId: null,
      clock: { now: () => new Date() },
      ttlSeconds: 3600,
      requiresMfa: true, // mfaVerified=false
    });
    // The login already created its own pending session row; our seed
    // is a separate row with a known plaintext.
    await txRunner.run(async (tx) => {
      await sessionRepo.save(tx, pendingSession);
    });

    // 5. THE ATTACK (pre-fix): refresh the pending session → tokens.
    //    Post-fix: 401 authentication.mfa.required, no tokens.
    await expect(
      refreshUc.execute({ refreshToken: pendingPlaintext }),
    ).rejects.toMatchObject({ code: 'authentication.mfa.required' });
    await expect(
      grantUc.execute({
        refreshToken: pendingPlaintext,
        organizationSlug: null,
      }),
    ).rejects.toMatchObject({ code: 'authentication.mfa.required' });

    // 6. Complete the second factor on the session.
    await verifyUc.execute({
      userId,
      sessionId: sessionId.value,
      code: authenticator.generate(secret),
    });

    // 7. The OAuth grant now mints an access token for the session.
    const issued = await grantUc.execute({
      refreshToken: pendingPlaintext,
      organizationSlug: null,
    });
    expect(issued.accessToken).toBeTruthy();
    expect(issued.accessToken.length).toBeGreaterThan(20);

    // 8. And the REST refresh rotates it normally.
    const rotated = await refreshUc.execute({ refreshToken: pendingPlaintext });
    expect(rotated.refreshToken).toBeTruthy();
    expect(rotated.refreshToken).not.toBe(pendingPlaintext);

    // IssueAccessTokenUseCase sanity check — we can re-issue too.
    const ref = await issueUc.execute({ userId, organizationSlug: null });
    expect(ref.accessToken).toBeTruthy();
  }, 60000);

  it('login with a valid inline mfaCode completes in one round-trip', async () => {
    const email = uniqueEmail('c1-inline');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });
    const enableResult = await enableUc.execute({
      userId: reg.userId,
      currentPassword: password,
    });
    await confirmUc.execute({
      userId: reg.userId,
      code: authenticator.generate(enableResult.secret),
    });

    // Inline second factor: same response shape as a no-MFA login.
    const login = await loginUc.execute({
      email,
      password,
      appDefaultOrgSlug: null,
      mfaCode: authenticator.generate(enableResult.secret),
    });
    expect(login.mfaRequired).toBe(false);
    expect(login.refreshToken).toBeTruthy();

    // The refresh grant accepts the session (mfaVerified at creation).
    const issued = await grantUc.execute({
      refreshToken: login.refreshToken!,
      organizationSlug: null,
    });
    expect(issued.accessToken).toBeTruthy();

    // An INVALID inline code is rejected (password already verified —
    // the error says nothing about the credential). Derive a definitely
    // wrong code from the current step (adjacent steps fail with
    // window=0 verification).
    const current = authenticator.generate(enableResult.secret);
    const wrongCode = String((Number(current) + 1) % 1_000_000).padStart(
      6,
      '0',
    );
    await expect(
      loginUc.execute({
        email,
        password,
        appDefaultOrgSlug: null,
        mfaCode: wrongCode,
      }),
    ).rejects.toMatchObject({ code: 'identity.mfa.code_invalid' });
  }, 60000);
});
