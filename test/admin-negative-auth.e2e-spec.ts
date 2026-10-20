/**
 * Admin surface negative auth — full integration.
 *
 * Pins the guard ORDER and failure codes on the REST admin controller
 * (`@UseGuards(IpAllowlistGuard, AdminApiKeyGuard)`):
 *
 *   1. `IpAllowlistGuard` runs FIRST. A request from a non-allowlisted
 *      IP is rejected before the key is even looked at — it never
 *      reaches `AdminApiKeyGuard`, so the response is Nest's generic
 *      403 (the guard fails closed by returning `false`; no key
 *      material is probed, which is what makes the order safe).
 *   2. From an allowlisted IP, a missing `Authorization` header →
 *      401 `admin.auth.missing`.
 *   3. A garbage (well-formed but unknown) key → 401
 *      `admin.auth.invalid`.
 *   4. A REVOKED key → 401 `admin.api_key.revoked` — the two-step
 *      lookup (V1.5 audit C5) deliberately distinguishes revoked from
 *      unknown so operators can diagnose; both stay 401 either way.
 *
 * The default test env allowlist is `127.0.0.1/32,::1/128`
 * (`.env`), so with `trust proxy` enabled we simulate both sides of
 * the allowlist via `X-Forwarded-For`.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { teardown } from './harness';
import { IssueAdminApiKeyUseCase } from '../src/administration/application/use-cases/issue-admin-api-key.use-case';

describe('Admin surface negative auth (integration)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let garbageToken: string;
  let revokedToken: string;

  const ALLOWED_IP = '127.0.0.1';
  const BLOCKED_IP = '10.9.9.9';

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
    // Trust proxy headers so `X-Forwarded-For` feeds `req.ip` and the
    // allowlist guard sees the simulated caller IP.
    (
      app.getHttpAdapter().getInstance() as unknown as {
        set: (k: string, v: unknown) => void;
      }
    ).set('trust proxy', true);

    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();

    const issueUc = app.get(IssueAdminApiKeyUseCase);

    // A key we issue and then revoke — the guard must treat it
    // exactly like an unknown token (admin.auth.invalid).
    const dead = await issueUc.execute({
      name: `neg-auth-revoked-${Date.now()}`,
      createdBy: 'test-admin@cerberus.local',
      ttlSeconds: 3600,
    });
    revokedToken = dead.plaintextToken;
    await prisma.adminApiKey.update({
      where: { id: dead.key.id },
      data: { revokedAt: new Date() },
    });

    // A well-formed but never-issued token (right shape, unknown
    // lookup value). Must be indistinguishable from the revoked key.
    garbageToken = `cerberus_test_${'0'.repeat(64)}`;
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
    await teardown();
  });

  it('rejects a non-allowlisted IP before any key check (403, no key probe)', async () => {
    // Even WITH a valid-looking Authorization header, the IP guard
    // runs first and the request never reaches key verification.
    const res = await request(app.getHttpServer())
      .get('/v1/admin/audit-log')
      .set('X-Forwarded-For', BLOCKED_IP)
      .set('authorization', `Bearer ${garbageToken}`);

    expect(res.status).toBe(403);
    // The guard fails closed by returning false, so Nest renders its
    // generic Forbidden body — no domain code leaks (in particular
    // nothing that would distinguish "bad IP" from "bad key").
    expect(res.body).toEqual({
      error: 'Forbidden',
      message: 'Forbidden resource',
      statusCode: 403,
    });
  });

  it('rejects a missing Authorization header from an allowlisted IP (401, admin.auth.missing)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/admin/api-keys')
      .set('X-Forwarded-For', ALLOWED_IP)
      .send({
        name: 'should-not-be-created',
        createdBy: 'test@cerberus.local',
      });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('admin.auth.missing');
  });

  it('rejects a garbage admin key (401, admin.auth.invalid)', async () => {
    const res = await request(app.getHttpServer())
      .get('/v1/admin/audit-log')
      .set('X-Forwarded-For', ALLOWED_IP)
      .set('authorization', `Bearer ${garbageToken}`);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('admin.auth.invalid');
  });

  it('rejects a revoked admin key (401, admin.api_key.revoked)', async () => {
    const res = await request(app.getHttpServer())
      .get('/v1/admin/audit-log')
      .set('X-Forwarded-For', ALLOWED_IP)
      .set('authorization', `Bearer ${revokedToken}`);

    expect(res.status).toBe(401);
    // VerifyAdminApiKeyUseCase's two-step lookup (V1.5 audit C5)
    // deliberately distinguishes a REVOKED key from an unknown one so
    // operators can tell "rotated away" apart from "typo" in the logs.
    // Unknown/garbage stays at admin.auth.invalid; both are 401.
    expect(res.body.code).toBe('admin.api_key.revoked');
  });
});
