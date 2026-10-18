/**
 * V1.6 OAuth2 client_credentials grant — full integration.
 *
 * Pins the RFC 6749 §4.4 service-to-service flow end-to-end:
 *   1. Register an App via /v1/apps (with initialScopes allowlist)
 *   2. POST /v1/oauth/token with grant_type=client_credentials →
 *      returns a JWT
 *   3. Decode the JWT, verify it carries `typ: 'app'`, `sub = appId`,
 *      `role: null`, `appId`, and the downgraded `scope` claim
 *   4. Verify the JWT signature against /.well-known/jwks.json
 *      (this is what Charon will do on the inbound side)
 *   5. Negative cases:
 *      - unknown client_id → app.auth.failed (mapped to 401
 *        by DomainErrorFilter with a `WWW-Authenticate: Basic
 *        realm="cerberus"` header, per RFC 6749 §5.2).
 *      - wrong client_secret → app.auth.failed
 *      - revoked app → app.auth.failed
 *      - app with empty allowedScopes → token mints with
 *        `scope: ''` (caller asked for scope X, gets nothing)
 *      - caller asks for scopes partially in the allowlist →
 *        only the intersection is granted (scope downgrade per
 *        RFC 6749 §3.3)
 *
 * Tests use real Postgres (no Docker bypass) — the AppRepository
 * goes through PrismaTransactionRunner against the live DB.
 */

import { createHash } from 'node:crypto';
import { importJWK, jwtVerify } from 'jose';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { teardown } from './harness';

describe('OAuth2 client_credentials grant (integration)', () => {
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
    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
    await teardown();
  });

  /**
   * Register an App via the existing public endpoint and return
   * the id + plaintext API key. Mirrors what Charon does on
   * first deploy (operator runs `POST /v1/apps` once, captures
   * the id + key).
   */
  async function registerApp(opts: {
    name: string;
    contactEmail?: string;
    defaultOrgSlug?: string | null;
    initialScopes?: string;
  }): Promise<{ appId: string; plaintextApiKey: string }> {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .send({
        name: opts.name,
        contactEmail: opts.contactEmail ?? 'app@cerberus.local',
        defaultOrgSlug: opts.defaultOrgSlug ?? null,
        ttlSeconds: 3600,
        initialScopes: opts.initialScopes,
      });
    expect(res.status).toBe(201);
    return {
      appId: res.body.app.id,
      plaintextApiKey: res.body.apiKey,
    };
  }

  /**
   * Decode the JWT payload + verify the signature against the
   * JWKS exposed at `/.well-known/jwks.json`. Returns the
   * decoded payload so the test can assert on claims.
   *
   * We don't need the full Nest ConfigService — just read the
   * env vars directly via process.env (they were loaded by the
   * test harness before PublicTestModule was constructed).
   */
  async function verifyJwt(token: string): Promise<Record<string, unknown>> {
    const jwksRes = await request(app.getHttpServer()).get(
      '/.well-known/jwks.json',
    );
    expect(jwksRes.status).toBe(200);
    const key = jwksRes.body.keys[0];
    const publicKey = await importJWK(key, 'RS256');
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: process.env.JWT_ISSUER ?? 'cerberus',
      audience: process.env.JWT_AUDIENCE_DEFAULT ?? 'cerberus-clients',
    });
    return payload;
  }

  /** Create a real organization with a unique slug. */
  async function createOrg(
    slug: string,
    name: string,
  ): Promise<{ id: string; slug: string }> {
    const org = await prisma.organization.create({ data: { slug, name } });
    return { id: org.id, slug: org.slug };
  }

  it('mints an app-bound JWT with typ:"app" + scope downgraded to allowlist', async () => {
    // Register with two allowed scopes; ask for three; expect only
    // the intersection to be granted.
    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-allow-${Date.now()}`,
      initialScopes: 'payments:read,payments:write',
    });

    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: plaintextApiKey,
        scope: 'payments:read payments:write escrows:release',
      });

    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
    expect(typeof res.body.expires_in).toBe('number');
    // Downgraded to the intersection (the third scope is not in
    // the allowlist).
    expect(res.body.scope).toBe('payments:read payments:write');
    // No refresh_token in the response — apps re-mint.
    expect(res.body.refresh_token).toBeUndefined();
    expect(typeof res.body.access_token).toBe('string');

    // Decode + verify the JWT.
    const payload = await verifyJwt(res.body.access_token);
    expect(payload.typ).toBe('app');
    expect(payload.sub).toBe(appId);
    expect(payload.appId).toBe(appId);
    expect(payload.role).toBeNull();
    expect(payload.scope).toBe('payments:read payments:write');
    expect(payload.org).toBeNull();
  });

  it('mints a tenant-bound JWT when the App has a defaultOrgSlug', async () => {
    // Register an org first (real test isolation — slug uniqueness
    // across tests).
    const orgSlug = `cc-org-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const org = await createOrg(orgSlug, 'CC Org');

    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-tenant-${Date.now()}`,
      defaultOrgSlug: orgSlug,
      initialScopes: 'payments:read',
    });

    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: plaintextApiKey,
      });
    expect(res.status).toBe(200);

    const payload = await verifyJwt(res.body.access_token);
    expect(payload.typ).toBe('app');
    expect(payload.org).toBe(org.id);
  });

  it('returns empty scope when the App has no allowedScopes (default)', async () => {
    // Default registration = empty allowedScopes.
    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-empty-${Date.now()}`,
    });

    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: plaintextApiKey,
        scope: 'payments:read payments:write',
      });
    expect(res.status).toBe(200);
    expect(res.body.scope).toBe('');
  });

  it('returns 401 (with WWW-Authenticate) when the client_id is unknown', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: '00000000-0000-0000-0000-000000000000',
        client_secret: 'anything',
      });
    expect(res.status).toBe(401);
    // The error code stays ambiguous so we don't leak whether
    // the client_id was wrong vs the client_secret — both
    // surface as `app.auth.failed` (RFC 6749 §5.2 `invalid_client`).
    expect(res.body.code).toBe('app.auth.failed');
    expect(res.headers['www-authenticate']).toBe('Basic realm="cerberus"');
  });

  it('returns 401 (with WWW-Authenticate) when the client_secret is wrong', async () => {
    const { appId } = await registerApp({
      name: `cc-bad-${Date.now()}`,
    });
    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: 'wrong-secret',
      });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('app.auth.failed');
    expect(res.headers['www-authenticate']).toBe('Basic realm="cerberus"');
  });

  it('returns 401 (with WWW-Authenticate) when the app has been revoked', async () => {
    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-revoked-${Date.now()}`,
    });
    // Operator-side revoke.
    await prisma.app.update({
      where: { id: appId },
      data: { revokedAt: new Date() },
    });

    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: plaintextApiKey,
      });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('app.auth.failed');
    expect(res.headers['www-authenticate']).toBe('Basic realm="cerberus"');
  });

  it('accepts X-Cerberus-App-Id + X-Cerberus-App-Secret headers as alternate transport', async () => {
    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-headers-${Date.now()}`,
      initialScopes: 'payments:read',
    });

    // The OAuth controller accepts either the body fields OR the
    // headers (same fields as register/login flows). Headers are
    // preferred by existing callers — verify they still work.
    const res = await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .set('x-cerberus-app-id', appId)
      .set('x-cerberus-app-secret', plaintextApiKey)
      .send({
        grant_type: 'client_credentials',
      });
    expect(res.status).toBe(200);
    const payload = await verifyJwt(res.body.access_token);
    expect(payload.typ).toBe('app');
    expect(payload.sub).toBe(appId);
  });

  it('writes an apps.token.issued audit event for every successful mint', async () => {
    const { appId, plaintextApiKey } = await registerApp({
      name: `cc-audit-${Date.now()}`,
      initialScopes: 'payments:read',
    });
    // Clear any prior audit rows for this app so the count is clean.
    await prisma.auditLog.deleteMany({
      where: { userId: appId, eventType: 'apps.token.issued' },
    });

    const before = await prisma.auditLog.count({
      where: { userId: appId, eventType: 'apps.token.issued' },
    });
    expect(before).toBe(0);

    await request(app.getHttpServer())
      .post('/v1/oauth/token')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        client_id: appId,
        client_secret: plaintextApiKey,
        scope: 'payments:read',
      })
      .expect(200);

    // The audit event is appended out-of-band via the outbox relay
    // (1s poll). Wait up to 3s for it to land.
    let after = 0;
    for (let i = 0; i < 75; i++) {
      after = await prisma.auditLog.count({
        where: { userId: appId, eventType: 'apps.token.issued' },
      });
      if (after >= 1) break;
      await new Promise((r) => setTimeout(r, 200));
    }
    expect(after).toBe(1);

    const row = await prisma.auditLog.findFirst({
      where: { userId: appId, eventType: 'apps.token.issued' },
    });
    expect(row).not.toBeNull();
    expect((row!.payload as { grantType: string }).grantType).toBe(
      'client_credentials',
    );
    expect((row!.payload as { appId: string }).appId).toBe(appId);
    expect((row!.payload as { scopes: string[] }).scopes).toEqual([
      'payments:read',
    ]);

    // Sanity: the row's userId column holds the App UUID (apps
    // don't have User UUIDs — the column is free-form text).
    expect(row!.userId).toBe(appId);

    // Sanity: the test itself should not assert any secret
    // material leaked into the audit row.
    const payloadStr = JSON.stringify(row!.payload);
    expect(payloadStr).not.toContain(plaintextApiKey);

    // Hard-verify the sha256-16-prefix of the plaintext in the
    // payload — if a future bug starts logging the secret
    // verbatim, the test catches it via this fingerprint.
    const hash16 = createHash('sha256')
      .update(plaintextApiKey, 'utf8')
      .digest('hex')
      .slice(0, 16);
    expect(payloadStr).not.toContain(hash16);
  });
});
