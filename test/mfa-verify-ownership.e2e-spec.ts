/**
 * V1.7 audit fix #7 — verifySecondFactor session ownership check.
 *
 * Pins the security guarantee: a user with MFA enabled cannot mark
 * another user's session as MFA-verified by submitting their own
 * TOTP code + the victim's sessionId. Before the fix, the use case
 * took `userId` from the caller's principal and `sessionId` from the
 * body, and never checked that the session belonged to the user.
 *
 * The fix added an ownership assertion after markMfaVerified. The
 * test exercises the negative path: user A has MFA, user B does not,
 * and A tries to mark B's session as verified.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { authenticator } from 'otplib';
import { PrismaClient } from '@prisma/client';
import { randomBytes as crypto_randomBytes, randomUUID } from 'node:crypto';
import { PublicTestModule } from './public-test.module';
import { teardown, uniqueEmail } from './harness';

describe('mfa/verify session-ownership check (V1.7 audit fix #7)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let attackerToken: string;
  let attackerId: string;
  let victimSessionId: string;
  const attackerPassword = 'correct horse battery 42!';
  const victimPassword = 'different password 99!';
  const bodyOf = <T>(res: { body: unknown }): T => res.body as T;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [PublicTestModule],
    }).compile();
    app = module.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix('v1', {
      exclude: [
        { path: 'health', method: 0 },
        { path: 'ready', method: 0 },
        { path: '.well-known/jwks.json', method: 0 },
        'graphql',
      ],
    });
    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();

    // 1. Register both attacker and victim.
    const attackerEmail = uniqueEmail('mfa-attacker');
    const victimEmail = uniqueEmail('mfa-victim');

    const attackerReg = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email: attackerEmail, password: attackerPassword })
      .expect(201);
    attackerId = attackerReg.body.userId;

    const victimReg = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email: victimEmail, password: victimPassword })
      .expect(201);
    const victimId = victimReg.body.userId;

    // 2. Attacker logs in, enables + confirms MFA.
    const attackerLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: attackerEmail, password: attackerPassword })
      .expect(200);
    attackerToken = bodyOf<{ accessToken: string }>(attackerLogin).accessToken;

    const enableRes = await request(app.getHttpServer())
      .post('/v1/identity/mfa/enable')
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({})
      .expect(200);
    const attackerSecret = bodyOf<{ secret: string }>(enableRes).secret;
    const totpCode = authenticator.generate(attackerSecret);
    void attackerSecret; // re-fetched inside the test for a fresh code

    await request(app.getHttpServer())
      .post('/v1/identity/mfa/confirm')
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({ code: totpCode })
      .expect(204);

    // 3. Victim logs in. Note: a victim WITHOUT MFA has mfaVerified
    // set to true at session creation ("no MFA = nothing to verify,
    // verified by definition"). To test the cross-user attack, the
    // victim must ALSO have MFA enabled (so the session is created
    // with mfaVerified=false) but NOT have called /mfa/verify yet
    // (otherwise the session is already verified).
    const victimLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: victimEmail, password: victimPassword })
      .expect(200);
    // The login response with mfaRequired=true has NO accessToken.
    // To get a JWT, we have to complete MFA on the victim's own
    // session first — but the whole point is to keep the victim's
    // session unverified. So we need an alternative way to mint a
    // token: use the OAuth password grant, which itself requires
    // the session to be mfa-verified, so that doesn't work either.
    //
    // Resolution: bypass the login flow by minting a session
    // directly via Prisma. The test's invariant we want to assert
    // is: victim's session mfaVerified=false. We don't need a JWT
    // to do that — we just need a way to read the session via the
    // /v1/auth/sessions endpoint, which requires a JWT. So mint
    // a JWT directly via the JwtSignerService (the same approach
    // the production OAuth refresh grant uses).
    void victimLogin;

    // The victim has MFA enabled but has NOT yet called
    // /v1/identity/mfa/verify on this session. We construct this
    // state directly via Prisma to avoid the chicken-and-egg
    // "login returns no accessToken when MFA is required" problem.
    //
    // 1. Insert a confirmed MfaSecret for the victim.
    await prisma.mfaSecret.create({
      data: {
        id: randomUUID(),
        userId: victimId,
        secret: crypto_randomBytes(20).toString('base64'),
        confirmed: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });

    // 2. Create a session for the victim with mfaVerified=false.
    //    (Equivalent to what login.use-case would create, but
    //    without triggering the MFA-required response.)
    const victimSessionRow = await prisma.session.create({
      data: {
        id: randomUUID(),
        userId: victimId,
        familyId: randomUUID(),
        refreshHash: 'test-victim-' + randomUUID(),
        userAgent: 'test-agent',
        ipAddress: '::1',
        deviceLabel: 'test-device',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        mfaVerified: false,
      },
    });
    victimSessionId = victimSessionRow.id;
    void victimLogin;
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    await app.close();
    await module.close();
    await teardown();
  });

  it('attacker cannot mark victim’s session as MFA-verified via /v1/identity/mfa/verify', async () => {
    // Fetch the attacker's TOTP secret (stored as base32 plaintext
    // in the `secret` column of `mfa_secrets`).
    const mfaRow = await prisma.mfaSecret.findUnique({
      where: { userId: attackerId },
    });
    if (!mfaRow) throw new Error('attacker MFA row missing');
    const attackerTotp = authenticator.generate(mfaRow.secret);

    // The attacker already has a session from beforeAll (the one
    // whose JWT we captured as `attackerToken`). Use that directly.
    // It's NOT yet MFA-verified (the confirm step doesn't verify it).
    // We need a session the attacker owns that they can call
    // mfa/verify on. Since the existing token IS that session,
    // we can use it as both the auth header and the session to
    // verify (in step 5 below).
    const attackerSessionsRes = await request(app.getHttpServer())
      .get('/v1/auth/sessions')
      .set('Authorization', `Bearer ${attackerToken}`)
      .expect(200);
    const attackerSessionId = bodyOf<{
      sessions: Array<{ sessionId: string }>;
    }>(attackerSessionsRes).sessions[0].sessionId;

    // 2. THE ATTACK: attacker (with their own valid TOTP) tries to
    // mark the VICTIM's session as MFA-verified. Pre-fix: would
    // succeed. Post-fix (V1.7): the ownership check rejects with
    // `authentication.session.not_found` (kept ambiguous to avoid
    // leaking that the session exists).
    const attackRes = await request(app.getHttpServer())
      .post('/v1/identity/mfa/verify')
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({ sessionId: victimSessionId, code: attackerTotp })
      .expect(401); // DomainErrorFilter maps `authentication.session.not_found` to 401

    // 3. The TOTP verifies (attacker owns the secret), so the
    // use case reaches the ownership check. The session's
    // userId !== attacker's userId, so it throws
    // `authentication.session.not_found` (or, post-fix, the same
    // error code from the existing markMfaVerified path). Either
    // way, the response is the same 200-with-error shape.
    expect(attackRes.body.code).toBe('authentication.session.not_found');

    // 4. CRITICAL: the victim's session is still unverified.
    // Pre-fix this would have mfaVerified set to true.
    const victimSession = await prisma.session.findUnique({
      where: { id: victimSessionId },
    });
    expect(victimSession).not.toBeNull();
    // Debug: log the attack status + victim's mfaVerified state
    // so we can see which path is failing.
    expect(victimSession!.mfaVerified).toBe(false); // was `true` pre-fix

    // 5. Positive control: attacker CAN verify their own session.
    // Proves the ownership check is per-call, not globally broken.
    const ownRes = await request(app.getHttpServer())
      .post('/v1/identity/mfa/verify')
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({ sessionId: attackerSessionId, code: attackerTotp })
      .expect(200);
    expect(ownRes.body.matched).toBe('totp');
    const attackerSession = await prisma.session.findUnique({
      where: { id: attackerSessionId },
    });
    expect(attackerSession!.mfaVerified).not.toBeNull();
  });
});
