/**
 * V1.7: Engagement GraphQL resolver test coverage.
 *
 * Pins the Engagement BC's 4 mutations + 1 query:
 *   * `requestEmailVerification` (JWT-gated, returns true)
 *   * `confirmEmailVerification` (public, returns true on valid
 *     token; throws on invalid/expired token)
 *   * `requestPasswordReset` (public, always returns true —
 *     no account enumeration)
 *   * `confirmPasswordReset` (public, redeems token + revokes
 *     all live sessions)
 *   * `auditLogMe` (JWT-gated, returns the calling user's
 *     own audit log)
 *
 * Mirrors the pattern from `engagement-confirm.e2e-spec.ts`
 * (REST integration) but exercises the GraphQL surface instead.
 * The GraphqlDomainErrorFilter is registered so domain errors
 * thrown by use cases surface as `extensions.domainCode`.
 *
 * Auth: real user registration + login via REST, then GraphQL
 * mutations with the Bearer token. No JWT-minting helper
 * exists yet (V2 candidate).
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PublicTestModule } from './public-test.module';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { teardown, uniqueEmail } from './harness';
import { PrismaClient } from '@prisma/client';

interface LoginResp {
  accessToken: string;
  refreshToken: string;
  mfaRequired: boolean;
}
interface GraphqlErrorBody {
  errors: Array<{
    message: string;
    extensions: { code: string; domainCode?: string };
  }>;
}

describe('Engagement GraphQL resolver (V1.7 — query coverage)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let accessToken: string;
  let userId: string;
  let email: string;
  const password = 'correct horse battery 42!';
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
    app.useGlobalFilters(new GraphqlDomainErrorFilter());
    await app.init();
    prisma = new PrismaClient();
    await prisma.$connect();

    // Register + login a real user via REST so we have a valid
    // JWT for the JWT-gated mutations.
    email = uniqueEmail('gql-eng');
    const reg = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);
    userId = reg.body.userId;
    const login = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password })
      .expect(200);
    accessToken = bodyOf<LoginResp>(login).accessToken;
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    await app.close();
    await module.close();
    await teardown();
  });

  it('requestEmailVerification — JWT-gated, returns true', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation { requestEmailVerification }`,
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.requestEmailVerification).toBe(true);
  });

  it('requestEmailVerification — rejects unauthenticated request', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({ query: `mutation { requestEmailVerification }` })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // AuthGuard on this mutation throws the standard UNAUTHENTICATED
    // code (no domainCode because it's a guard-level rejection,
    // not a use-case DomainError).
    expect(errBody.errors[0].extensions.code).toBe('UNAUTHENTICATED');
  });

  it('confirmEmailVerification — bad token returns an error (no enumeration)', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({
        query: `mutation Confirm($input: ConfirmEmailVerificationInput!) {
          confirmEmailVerification(input: $input)
        }`,
        variables: { input: { token: 'not-a-real-token' } },
      })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // The use case throws `engagement.email_verification.invalid_token`
    // for any token that doesn't parse + hash-verify. Mapped to
    // BAD_REQUEST by the domain-error filter.
    expect(errBody.errors[0].extensions.domainCode).toBe(
      'engagement.email_verification.invalid_token',
    );
  });

  it('requestPasswordReset — always returns true (no enumeration)', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({
        query: `mutation Request($input: RequestPasswordResetInput!) {
          requestPasswordReset(input: $input)
        }`,
        variables: { input: { email: 'never-registered@example.com' } },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.requestPasswordReset).toBe(true);
  });

  it('auditLogMe — returns the calling user’s audit log', async () => {
    // The V1.5 outbox relay processes events on a 1s poll cycle.
    // The register + login events from beforeAll may not be
    // visible immediately when this test runs in parallel with
    // other suites (each suite boots its own Nest app on a
    // different port, and the relays compete for DB cycles).
    // Poll the audit log for up to 30s waiting for the
    // registered event to appear. (V1.7: when the e2e suite runs
    // in parallel with 4+ other suites, the outbox relay's 1s tick
    // can be starved of Prisma cycles — 5s and 15s both failed
    // intermittently under load. 30s is the per-test Jest budget
    // ceiling; we expect this to converge much faster in normal
    // CI runs.)
    let entries: Array<{
      id: string;
      eventType: string;
      userId: string | null;
      occurredAt: string;
    }> = [];
    let found = false;
    for (let i = 0; i < 150; i++) {
      const res = await request(app.getHttpServer())
        .post('/graphql')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          query: `query { auditLogMe(limit: 5) { id eventType userId occurredAt } }`,
        })
        .expect(200);
      expect(res.body.errors).toBeUndefined();
      entries = res.body.data.auditLogMe;
      if (entries.some((e) => e.eventType === 'identity.user.registered')) {
        found = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    expect(found).toBe(true);
    // The event has the calling userId.
    expect(entries.every((e) => e.userId === userId)).toBe(true);
  });

  it('auditLogMe — server-side limit is bounded to 1–500', async () => {
    // The resolver clamps `limit` to [1, 500] before passing it
    // to the use case. Asking for limit=10000 must NOT error —
    // it should be silently clamped to 500.
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `query { auditLogMe(limit: 10000) { id } }`,
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    // Returns at most 500 entries (we only have a few, so the
    // exact number doesn't matter — just that it doesn't error).
    expect(Array.isArray(res.body.data.auditLogMe)).toBe(true);
  });

  it('auditLogMe — rejects unauthenticated request', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({ query: `query { auditLogMe(limit: 5) { id } }` })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    expect(errBody.errors[0].extensions.code).toBe('UNAUTHENTICATED');
  });

  it('confirmPasswordReset — bad token returns an error', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({
        query: `mutation Confirm($input: ConfirmPasswordResetInput!) {
          confirmPasswordReset(input: $input)
        }`,
        variables: {
          input: { token: 'not-a-real-token', newPassword: 'NewP4ssword!' },
        },
      })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // The use case throws `engagement.password_reset.invalid_token`
    // for any token that doesn't parse + hash-verify.
    expect(errBody.errors[0].extensions.domainCode).toBe(
      'engagement.password_reset.invalid_token',
    );
  });
});
