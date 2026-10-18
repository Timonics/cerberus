/**
 * V1.7 ProductionAdminGuard — full integration.
 *
 * Pins the production-only admin gate on `POST /v1/apps`:
 *   * In dev/staging (NODE_ENV !== 'production' AND
 *     REQUIRE_ADMIN_FOR_REGISTRATION !== 'true'): the guard
 *     passes through — self-service registration is open.
 *   * In production (NODE_ENV === 'production'): a valid admin
 *     `Authorization: Bearer *** header is required.
 *   * When `REQUIRE_ADMIN_FOR_REGISTRATION=true`: the guard
 *     also forces the gate on in non-production environments
 *     (the toggle is there for operators who want a staging
 *     env to mirror prod's posture).
 *
 * Tests in this file force the gate on by setting the env var
 * at process start (NODE_ENV stays 'test' for the test runner;
 * we only override `REQUIRE_ADMIN_FOR_REGISTRATION` to exercise
 * the actual guard logic without actually booting Cerberus in
 * production mode).
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { teardown, uniqueEmail } from './harness';
import { createHash } from 'node:crypto';
import { IssueAdminApiKeyUseCase } from '../src/administration/application/use-cases/issue-admin-api-key.use-case';

describe('ProductionAdminGuard (V1.7)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let adminToken: string;
  let adminTokenRevoked: string;

  beforeAll(async () => {
    // Force the production guard ON. The test runner's NODE_ENV
    // is 'test' (we don't want to actually run the production
    // listener config), so we set the env-var override that the
    // guard checks.
    process.env.REQUIRE_ADMIN_FOR_REGISTRATION = 'true';

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

    // Issue two admin keys — one valid, one revoked. The guard
    // is meant to allow the valid one and reject the revoked.
    const issueUc = app.get(IssueAdminApiKeyUseCase);
    const live = await issueUc.execute({
      name: `prod-guard-live-${Date.now()}`,
      createdBy: 'test-admin@cerberus.local',
      ttlSeconds: 3600,
    });
    adminToken = live.plaintextToken;

    const dead = await issueUc.execute({
      name: `prod-guard-dead-${Date.now()}`,
      createdBy: 'test-admin@cerberus.local',
      ttlSeconds: 3600,
    });
    adminTokenRevoked = dead.plaintextToken;
    // Revoke the second one so the guard should reject it.
    await prisma.adminApiKey.update({
      where: { id: dead.key.id },
      data: { revokedAt: new Date() },
    });
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
    delete process.env.REQUIRE_ADMIN_FOR_REGISTRATION;
    await teardown();
  });

  it('rejects register with no Authorization header (401, admin.auth.missing)', async () => {
    const res = await request(app.getHttpServer()).post('/v1/apps').send({
      name: 'prod-guard-noauth',
      contactEmail: 'noauth@cerberus.local',
      ttlSeconds: 3600,
    });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('admin.auth.missing');
  });

  it('rejects register with a malformed Authorization header (401)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('authorization', 'NotBearer some-token')
      .send({
        name: 'prod-guard-bad',
        contactEmail: 'bad@cerberus.local',
        ttlSeconds: 3600,
      });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('admin.auth.missing');
  });

  it('rejects register with a revoked admin key (401, admin.auth.invalid)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('authorization', `Bearer ${adminTokenRevoked}`)
      .send({
        name: 'prod-guard-revoked',
        contactEmail: 'revoked@cerberus.local',
        ttlSeconds: 3600,
      });
    expect(res.status).toBe(401);
    // The lookup-token service returns null for revoked keys
    // (the underlying findActiveByLookupToken filters on
    // revokedAt IS NULL), which the guard maps to
    // admin.auth.invalid.
    expect(res.body.code).toBe('admin.auth.invalid');
  });

  it('accepts register with a valid admin key (201)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('authorization', `Bearer ${adminToken}`)
      .send({
        name: `prod-guard-ok-${Date.now()}`,
        contactEmail: uniqueEmail('prod-guard'),
        ttlSeconds: 3600,
      });
    expect(res.status).toBe(201);
    expect(res.body.app.id).toBeTruthy();
    expect(res.body.apiKey).toBeTruthy();

    // Sanity: the plaintext token in the Authorization header
    // is NOT in the response body (no token echo).
    expect(JSON.stringify(res.body)).not.toContain(adminToken);
    // Sanity: the sha256-16 fingerprint of the token is also
    // not in the body (catches a future bug that logs the
    // secret verbatim).
    const hash16 = createHash('sha256')
      .update(adminToken, 'utf8')
      .digest('hex')
      .slice(0, 16);
    expect(JSON.stringify(res.body)).not.toContain(hash16);
  });
});

describe('ProductionAdminGuard: dev-mode pass-through', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;

  beforeAll(async () => {
    // Make sure the override is OFF for this describe.
    delete process.env.REQUIRE_ADMIN_FOR_REGISTRATION;
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
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
    await teardown();
  });

  it('register works without an admin header in dev (NODE_ENV=test)', async () => {
    // Sanity: in NODE_ENV=test, the guard is fully open. This
    // is the existing behavior — apps-lifecycle + oauth-client-
    // credentials tests rely on it. We pin it here so a future
    // change to the guard's default can't silently break them.
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .send({
        name: `dev-mode-${Date.now()}`,
        contactEmail: uniqueEmail('dev-mode'),
        ttlSeconds: 3600,
      });
    expect(res.status).toBe(201);
  });
});
