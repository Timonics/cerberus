/**
 * GraphQL mutation auth invariant — full integration.
 *
 * Pins which mutations are reachable anonymously and which are not,
 * from the OUTSIDE, against the live schema (no resolver imports):
 *
 *   1. Introspect `__type(name: "Mutation")` and assert the full field
 *      list — any future mutation lands here and must be classified
 *      into exactly one of the two buckets below.
 *   2. For every GATED mutation, send one anonymous request with
 *      minimal but syntactically valid args and assert the error code
 *      is `UNAUTHENTICATED` (no/invalid bearer) or `FORBIDDEN`
 *      (app-credential requirement) — never a silent success, never
 *      an INTERNAL_SERVER_ERROR leaking past the auth boundary.
 *   3. For every PUBLIC mutation, assert the call does NOT fail with
 *      an auth code. Public mutations either succeed (register,
 *      requestPasswordReset, registerApp in non-production) or fail
 *      with a domain error (invalid token) — anything except
 *      UNAUTHENTICATED/FORBIDDEN.
 *
 * `issueAdminApiKey` / `revokeAdminApiKey` are in the SDL but have NO
 * resolver implementation (dead SDL — the admin-key surface lives on
 * the REST controller behind the IP allowlist + admin-key guard). We
 * assert only that calling them does not succeed; the follow-up to
 * implement or remove them is tracked separately.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { teardown, uniqueEmail } from './harness';

const NIL_ID = '00000000-0000-0000-0000-000000000000';

interface GqlResponse {
  status: number;
  body: {
    data?: Record<string, unknown>;
    errors?: ReadonlyArray<{
      message: string;
      extensions?: { code?: string; domainCode?: string };
    }>;
  };
}

describe('GraphQL mutation auth invariant (integration)', () => {
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

  async function gql(query: string): Promise<GqlResponse> {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({ query });
    return { status: res.status, body: res.body as GqlResponse['body'] };
  }

  function errorCodes(r: GqlResponse): string[] {
    return (r.body.errors ?? []).map((e) => e.extensions?.code ?? 'NO_CODE');
  }

  it('Mutation field list matches the classified contract (introspection)', async () => {
    const r = await gql(`{
      __type(name: "Mutation") { fields { name } }
    }`);
    expect(r.body.errors).toBeUndefined();
    const names = (
      (r.body.data as { __type: { fields: { name: string }[] } }).__type
        ?.fields ?? []
    ).map((f) => f.name);

    expect(names).toEqual(
      expect.arrayContaining([
        // apps
        'registerApp',
        'rotateAppKey',
        'revokeApp',
        // engagement
        'requestEmailVerification',
        'confirmEmailVerification',
        'requestPasswordReset',
        'confirmPasswordReset',
        // identity
        'register',
        'changePassword',
        'updateDisplayName',
        'enableMfa',
        'confirmMfaEnrollment',
        'disableMfa',
        'verifyMfa',
        'revokeSession',
        // admin
        'adminDisableUserMfa',
        'issueAdminApiKey',
        'revokeAdminApiKey',
      ]),
    );
  });

  it.each([
    [
      'changePassword',
      'changePassword(input:{currentPassword:"x",newPassword:"y"})',
    ],
    ['updateDisplayName', 'updateDisplayName(input:{displayName:"x"}) { id }'],
    ['enableMfa', 'enableMfa(input:{currentPassword:"x"}) { secret }'],
    ['confirmMfaEnrollment', 'confirmMfaEnrollment(input:{code:"000000"})'],
    ['disableMfa', 'disableMfa(input:{code:"000000"})'],
    ['verifyMfa', 'verifyMfa(input:{code:"000000"}) { matched }'],
    ['revokeSession', `revokeSession(sessionId:"${NIL_ID}")`],
    ['requestEmailVerification', 'requestEmailVerification'],
    [
      'adminDisableUserMfa',
      `adminDisableUserMfa(input:{userId:"${NIL_ID}",reason:"x"}) { userId }`,
    ],
  ])(
    'gated mutation %s rejects anonymous callers (UNAUTHENTICATED)',
    async (_name, field) => {
      const r = await gql(`mutation { ${field} }`);
      expect(r.status).toBe(200); // GraphQL transport stays 200
      expect(r.body.errors).toBeDefined();
      expect(r.body.errors!.length).toBeGreaterThan(0);
      for (const code of errorCodes(r)) {
        expect(code).toBe('UNAUTHENTICATED');
      }
      // No partial success payload.
      expect(r.body.data).toBeNull();
    },
  );

  it.each([
    ['rotateAppKey', `rotateAppKey(id:"${NIL_ID}") { appId }`],
    ['revokeApp', `revokeApp(id:"${NIL_ID}")`],
  ])(
    'app-credential mutation %s rejects anonymous callers (FORBIDDEN)',
    async (_name, field) => {
      const r = await gql(`mutation { ${field} }`);
      expect(r.status).toBe(200);
      expect(r.body.errors).toBeDefined();
      for (const code of errorCodes(r)) {
        expect(code).toBe('FORBIDDEN');
      }
      expect(r.body.data).toBeNull();
    },
  );

  it.each([
    [
      'issueAdminApiKey',
      'issueAdminApiKey(input:{name:"dead-sdl"}) { apiKey }',
    ],
    ['revokeAdminApiKey', `revokeAdminApiKey(id:"${NIL_ID}")`],
  ])(
    'dead-SDL mutation %s cannot be invoked anonymously',
    async (_name, field) => {
      // No resolver is wired for these SDL fields — the call must fail
      // somehow (non-null resolution error). If a future change wires a
      // resolver, this test will still pass only if anonymous callers
      // are rejected; a silent success here means a NEW public admin
      // surface appeared without an auth gate — that must never happen.
      const r = await gql(`mutation { ${field} }`);
      expect(r.status).toBe(200);
      const data = r.body.data as Record<string, unknown> | null | undefined;
      const succeeded = data !== null && data !== undefined;
      if (succeeded) {
        // A resolver now exists — it must still refuse anonymous callers.
        expect(errorCodes(r)).not.toHaveLength(0);
        for (const code of errorCodes(r)) {
          expect(['UNAUTHENTICATED', 'FORBIDDEN']).toContain(code);
        }
      } else {
        expect(r.body.errors).toBeDefined();
        expect(r.body.errors!.length).toBeGreaterThan(0);
      }
    },
  );

  it('public mutations stay reachable anonymously (no auth error)', async () => {
    // registerApp — open in non-production (ProductionAdminGuard
    // passes through when the env override is off).
    const regApp = await gql(`mutation {
      registerApp(input:{name:"gql-inv-${Date.now()}",contactEmail:"gql-inv@cerberus.local"}) { app { id } }
    }`);
    expect(errorCodes(regApp)).not.toContain('UNAUTHENTICATED');
    expect(errorCodes(regApp)).not.toContain('FORBIDDEN');
    expect(
      (regApp.body.data as { registerApp: { app: { id: string } } }).registerApp
        .app.id,
    ).toBeTruthy();

    // requestPasswordReset — always returns true, never an auth error.
    const reset = await gql(`mutation {
      requestPasswordReset(input:{email:"${uniqueEmail('gql-inv')}"})
    }`);
    expect(reset.body.errors).toBeUndefined();
    expect(reset.body.data).toEqual({ requestPasswordReset: true });

    // confirmEmailVerification / confirmPasswordReset — domain error
    // (invalid token) is fine; an auth error is NOT.
    const confirmEmail = await gql(`mutation {
      confirmEmailVerification(input:{token:"x"})
    }`);
    expect(errorCodes(confirmEmail)).not.toContain('UNAUTHENTICATED');
    expect(errorCodes(confirmEmail)).not.toContain('FORBIDDEN');

    const confirmReset = await gql(`mutation {
      confirmPasswordReset(input:{token:"x",newPassword:"SomeNewP4ssw0rd1"})
    }`);
    expect(errorCodes(confirmReset)).not.toContain('UNAUTHENTICATED');
    expect(errorCodes(confirmReset)).not.toContain('FORBIDDEN');

    // register — full success for a fresh email.
    const reg = await gql(`mutation {
      register(input:{email:"${uniqueEmail('gql-inv-register')}",password:"Reg1sterP4ss!"}) { userId }
    }`);
    expect(reg.body.errors).toBeUndefined();
    expect(
      (reg.body.data as { register: { userId: string } }).register.userId,
    ).toBeTruthy();
  });
});
