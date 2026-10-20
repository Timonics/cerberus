/**
 * H-8 — account lockout behavior (2026-10-19 audit fix).
 *
 * Pins the two-layer lockout at the HTTP layer:
 *   1. Per-(email, ip) tier: 5 failed attempts from ONE IP within
 *      15 minutes → `authentication.account_locked` (the OWASP
 *      LockoutPolicy tiers, DB-enforced via Credential.lockedUntil).
 *   2. Account-wide (H-8): 10 failed attempts against one email from
 *      ANY IPs within 15 minutes → the same 401
 *      `authentication.account_locked`. Catches the IP-rotating
 *      brute-forcer that the per-IP tiers never see.
 *   3. A SUCCESSFUL login clears both windows (and unlocks the
 *      credential) — a user who recovers their password isn't one
 *      burst away from another lock.
 *   4. The OAuth2 password grant passes the real client IP (not a
 *      collapsed '0.0.0.0') — proven via the ipAddress recorded on
 *      the `authentication.login.failed` audit row.
 *
 * Requests simulate IP rotation via X-Forwarded-For with
 * `trust proxy` enabled (same pattern as
 * per-email-rate-limit.e2e-spec.ts).
 *
 * Request budgets stay under the default per-email throttle cap
 * (10/min) so the throttle guard doesn't shadow the lockout signal.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { resetRateLimits, teardown, uniqueEmail } from './harness';

describe('H-8 — account lockout (integration)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;

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
    // Trust X-Forwarded-For so supertest can simulate IP rotation.
    (
      app.getHttpAdapter().getInstance() as unknown as {
        set: (k: string, v: unknown) => void;
      }
    ).set('trust proxy', true);
    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();
    // The throttle counters live in the SHARED Redis (not per-process),
    // so parallel suites and prior runs count against the same
    // 10-registers/min/IP budget. Reset before we start so the lockout
    // signal isn't shadowed by a 429.
    await resetRateLimits();
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await app.close();
    await module.close();
    await teardown();
  });

  const login = (email: string, password: string, ip: string) =>
    request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password })
      .set('X-Forwarded-For', ip);

  it('per-(email, ip) tier: 5 failures from one IP → account_locked', async () => {
    const email = uniqueEmail('lock-tier');
    const password = 'Correct horse battery 42';
    await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);

    // 4 failures → still the ambiguous invalid_credentials.
    for (let i = 0; i < 4; i++) {
      const res = await login(email, 'wrong password ' + i, '10.1.0.1');
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('authentication.invalid_credentials');
    }
    // The 5th failure trips the tier → account_locked.
    const fifth = await login(email, 'wrong password 5', '10.1.0.1');
    expect(fifth.status).toBe(401);
    expect(fifth.body.code).toBe('authentication.account_locked');

    // Even the CORRECT password is refused while locked.
    const locked = await login(email, password, '10.1.0.1');
    expect(locked.status).toBe(401);
    expect(locked.body.code).toBe('authentication.account_locked');

    // DB-level enforcement: the credential row carries lockedUntil.
    const user = await prisma.user.findUnique({ where: { email } });
    const credential = await prisma.credential.findUnique({
      where: { userId: user!.id },
    });
    expect(credential?.lockedUntil).not.toBeNull();
    expect(credential!.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
  }, 60000);

  it('account-wide: 10 failures from DISTINCT IPs → account_locked', async () => {
    const email = uniqueEmail('lock-account');
    const password = 'Correct horse battery 42';
    await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);

    // 9 single failures from 9 distinct IPs — each below the per-IP
    // tier, no lock yet.
    for (let i = 1; i <= 9; i++) {
      const res = await login(email, 'wrong password', `10.2.0.${i}`);
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('authentication.invalid_credentials');
    }
    // The 10th failure (10th distinct IP) trips the account-wide
    // threshold. (We stop here — an 11th same-email request within
    // the minute would trip the 10/min per-email THROTTLE, not the
    // lockout, and test 1 already pins the correct-password-refused
    // behavior on the locked account.)
    const tenth = await login(email, 'wrong password', '10.2.0.10');
    expect(tenth.status).toBe(401);
    expect(tenth.body.code).toBe('authentication.account_locked');
  }, 60000);

  it('a successful login clears the failure windows', async () => {
    const email = uniqueEmail('lock-clear');
    const password = 'Correct horse battery 42';
    await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);

    // 4 failures (just under the tier).
    for (let i = 0; i < 4; i++) {
      await login(email, 'wrong password ' + i, '10.3.0.1');
    }
    // Success clears both the per-(email,ip) window and the
    // account-wide window.
    const ok = await login(email, password, '10.3.0.1');
    expect(ok.status).toBe(200);

    // Another 4 failures — if the windows were NOT cleared, the
    // account-wide count would be 8 and two more would lock it; and
    // the per-IP count of 8 would be past the tier. We do 4 and
    // assert the account is still open.
    for (let i = 0; i < 4; i++) {
      const res = await login(email, 'wrong password x' + i, '10.3.0.1');
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('authentication.invalid_credentials');
    }
    const stillOpen = await login(email, password, '10.3.0.1');
    expect(stillOpen.status).toBe(200);
  }, 60000);

  it('OAuth2 password grant records the REAL client IP on failed-login audit', async () => {
    const email = uniqueEmail('lock-oauth-ip');
    const password = 'Correct horse battery 42';
    await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);

    // One failed password-grant attempt from a spoofable IP.
    await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .set('X-Forwarded-For', '10.4.0.7')
      .send({
        grant_type: 'password',
        username: email,
        password: 'wrong password',
      })
      .expect(401);

    // The audit row records the forwarded IP — proving the grant
    // passes the real client IP into the login use-case (pre-fix it
    // collapsed to '0.0.0.0', destroying per-IP forensics).
    let audit = null;
    for (let i = 0; i < 75; i++) {
      audit = await prisma.auditLog.findFirst({
        where: {
          eventType: 'authentication.login.failed',
          payload: { path: ['ipAddress'], equals: '10.4.0.7' },
        },
        orderBy: { createdAt: 'desc' },
      });
      if (audit) break;
      await new Promise((r) => setTimeout(r, 200));
    }
    expect(audit).not.toBeNull();
  }, 60000);
});
