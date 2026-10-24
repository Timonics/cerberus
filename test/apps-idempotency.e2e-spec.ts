/**
 * App-registration idempotency (HTTP-level).
 *
 * Pins the `Idempotency-Key` contract on POST /v1/apps:
 *   1. First call with a key → 201, apiKey + idempotentReplay:false.
 *   2. Retry with the SAME key → same app id, apiKey null,
 *      idempotentReplay:true (the plaintext is never re-issued).
 *   3. Same key with a DIFFERENT body → still the ORIGINAL app
 *      (the key, not the body, decides a replay).
 *   4. No key → every call creates a new app (backwards compat).
 *   5. Key longer than 128 chars → 400 app.idempotency_key.invalid.
 *   6. After the app is revoked, the key is consumed → 400.
 *
 * Uses PublicTestModule + supertest against real Postgres, same
 * harness pattern as oauth-client-credentials.e2e-spec.ts.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PublicTestModule } from './public-test.module';
import { teardown } from './harness';

describe('App registration idempotency (HTTP)', () => {
  let module: TestingModule;
  let app: INestApplication;

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
  });

  afterAll(async () => {
    if (module) await module.close();
    await teardown();
  });

  const validBody = (name: string) => ({
    name,
    contactEmail: 'idem@cerberus.local',
    ttlSeconds: 3600,
  });

  it('first call with a key creates; retry with same key replays without re-issuing the key', async () => {
    const key = `idem-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

    const first = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('idem-app-a'));
    expect(first.status).toBe(201);
    expect(first.body.apiKey).toBeTruthy();
    expect(first.body.idempotentReplay).toBe(false);

    const retry = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('idem-app-a'));
    expect(retry.status).toBe(201);
    expect(retry.body.app.id).toBe(first.body.app.id);
    expect(retry.body.apiKey).toBeNull();
    expect(retry.body.idempotentReplay).toBe(true);
  });

  it('same key with a different body still returns the ORIGINAL app', async () => {
    const key = `idem-body-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

    const first = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('original-name'));
    expect(first.status).toBe(201);

    const retry = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('changed-name'));
    expect(retry.status).toBe(201);
    expect(retry.body.app.id).toBe(first.body.app.id);
    expect(retry.body.app.name).toBe('original-name');
    expect(retry.body.apiKey).toBeNull();
  });

  it('no key → every call creates a new app', async () => {
    const one = await request(app.getHttpServer())
      .post('/v1/apps')
      .send(validBody('idem-nokey'));
    const two = await request(app.getHttpServer())
      .post('/v1/apps')
      .send(validBody('idem-nokey'));
    expect(one.status).toBe(201);
    expect(two.status).toBe(201);
    expect(one.body.app.id).not.toBe(two.body.app.id);
  });

  it('key longer than 128 chars is rejected', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', 'x'.repeat(129))
      .send(validBody('idem-long-key'));
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('app.idempotency_key.invalid');
  });

  it('a revoked app consumes its key — replaying it is rejected', async () => {
    const key = `idem-revoke-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

    const first = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('idem-to-revoke'));
    expect(first.status).toBe(201);
    const appId = first.body.app.id as string;
    const apiKey = first.body.apiKey as string;

    const revoke = await request(app.getHttpServer())
      .delete(`/v1/apps/${appId}`)
      .set('X-Cerberus-App-Id', appId)
      .set('X-Cerberus-App-Secret', apiKey);
    expect(revoke.status).toBe(204);

    const replay = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Idempotency-Key', key)
      .send(validBody('idem-to-revoke'));
    expect(replay.status).toBe(400);
    expect(replay.body.code).toBe('app.idempotency_key.invalid');
  });
});
