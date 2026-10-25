/**
 * Authentication GraphQL resolver coverage (login / refresh / logout).
 *
 * Pins the GraphQL parity for the REST Authentication session
 * endpoints:
 *
 *   1. `login` — happy path returns the full token pair (mfaRequired:
 *      false) and the access token works on `Identity.me`.
 *   2. `login` — wrong password surfaces authentication.invalid_credentials.
 *   3. `login` — MFA-pending branch returns ONLY the scoped mfaToken
 *      (no access/refresh token — audit fix C1); `Identity.verifyMfa`
 *      then completes the login and returns the real token pair.
 *   4. `refresh` — rotates the refresh token and issues a fresh pair.
 *   5. `logout` — revoking the session; a later refresh fails.
 *   6. App-credential headers are fail-closed (partial → INPUT_INVALID,
 *      bogus pair → UNAUTHENTICATED), same as the REST endpoint.
 *
 * Uses PublicTestModule + supertest against real Postgres, same
 * harness pattern as engagement-graphql.e2e-spec.ts.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { authenticator } from 'otplib';
import { PublicTestModule } from './public-test.module';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { RotateSigningKeyUseCase } from '../src/authorization/application/use-cases/rotate-signing-key.use-case';
import { teardown, uniqueEmail } from './harness';

interface LoginPayload {
  mfaRequired: boolean;
  accessToken: string | null;
  refreshToken: string | null;
  mfaToken: string | null;
  sessionId: string;
  userId: string;
  familyId: string;
  expiresAt: string;
  expiresIn: number | null;
}
interface RefreshPayload {
  refreshToken: string;
  accessToken: string;
  sessionId: string;
  userId: string;
  familyId: string;
  expiresAt: string;
  expiresIn: number;
}
interface GraphqlErrorBody {
  errors: Array<{
    message: string;
    extensions: { code: string; domainCode?: string };
  }>;
}

const LOGIN_MUTATION = `mutation Login($input: LoginInput!) {
  login(input: $input) {
    mfaRequired accessToken refreshToken mfaToken
    sessionId userId familyId expiresAt expiresIn
  }
}`;

describe('Authentication GraphQL resolver (login / refresh / logout)', () => {
  let module: TestingModule;
  let app: INestApplication;
  const password = 'correct horse battery 42!';
  const bodyOf = <T>(res: { body: unknown }): T => res.body as T;
  // GraphQL envelopes carry results under `data` — errors under
  // `errors`. Use dataOf when asserting on the result shape.
  const dataOf = <T>(res: { body: unknown }): T =>
    (res.body as { data: T }).data;

  const gql = (
    query: string,
    variables?: Record<string, unknown>,
    bearer?: string,
    headers?: Record<string, string>,
  ) => {
    const req = request(app.getHttpServer())
      .post('/graphql')
      .set('Content-Type', 'application/json');
    if (bearer) req.set('Authorization', `Bearer ${bearer}`);
    if (headers) for (const [k, v] of Object.entries(headers)) req.set(k, v);
    return req.send({ query, variables });
  };

  const register = async (suffix: string) => {
    const email = uniqueEmail(`authgql-${suffix}`);
    const res = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password });
    expect(res.status).toBe(201);
    return email;
  };

  const restLogin = async (email: string) => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password });
    expect(res.status).toBe(200);
    return res.body.accessToken as string;
  };

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

    // Fresh databases have no signing key (the operator normally
    // creates one via POST /v1/oauth/admin/keys/rotate). Token
    // issuance needs one, so bootstrap it here — the use-case is
    // idempotent within its 1-minute dedup window.
    await module.get(RotateSigningKeyUseCase).execute();
  });

  afterAll(async () => {
    await app.close();
    await module.close();
    await teardown();
  });

  it('login happy path returns the token pair; accessToken works on me', async () => {
    const email = await register('happy');
    const res = await gql(LOGIN_MUTATION, {
      input: { email, password, userAgent: 'authgql-test' },
    });
    expect(res.status).toBe(200);
    expect(res.body.errors).toBeUndefined();
    const login = dataOf<{ login: LoginPayload }>(res).login;
    expect(login.mfaRequired).toBe(false);
    expect(login.accessToken).toBeTruthy();
    expect(login.refreshToken).toBeTruthy();
    expect(login.mfaToken).toBeNull();
    expect(login.sessionId).toBeTruthy();
    expect(login.userId).toBeTruthy();
    expect(login.familyId).toBeTruthy();
    expect(login.expiresAt).toBeTruthy();
    expect(login.expiresIn).toBeGreaterThan(0);

    const me = await gql(
      `{ me { id email } }`,
      undefined,
      login.accessToken as string,
    );
    expect(me.body.errors).toBeUndefined();
    expect(me.body.data.me.email).toBe(email);
  });

  it('login with a wrong password surfaces the domain code', async () => {
    const email = await register('wrongpw');
    const res = await gql(LOGIN_MUTATION, {
      input: { email, password: 'definitely not the password' },
    });
    const body = bodyOf<GraphqlErrorBody>(res);
    expect(body.errors).toBeDefined();
    expect(body.errors[0].extensions.domainCode).toBe(
      'authentication.invalid_credentials',
    );
  });

  it('MFA-pending login returns only the scoped mfaToken; verifyMfa completes with the token pair', async () => {
    const email = await register('mfa');
    const token = await restLogin(email);

    // Enroll + confirm MFA via REST (established otplib pattern).
    const enable = await request(app.getHttpServer())
      .post('/v1/identity/mfa/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ currentPassword: password });
    expect(enable.status).toBe(200);
    const { secret } = enable.body as { secret: string };
    const confirm = await request(app.getHttpServer())
      .post('/v1/identity/mfa/confirm')
      .set('Authorization', `Bearer ${token}`)
      .send({ code: authenticator.generate(secret) });
    expect(confirm.status).toBe(204);

    // GraphQL login → MFA-pending branch.
    const pending = await gql(LOGIN_MUTATION, {
      input: { email, password },
    });
    expect(pending.body.errors).toBeUndefined();
    const login = dataOf<{ login: LoginPayload }>(pending).login;
    expect(login.mfaRequired).toBe(true);
    expect(login.mfaToken).toBeTruthy();
    // C1 invariant: no usable token before the second factor.
    expect(login.accessToken).toBeNull();
    expect(login.refreshToken).toBeNull();

    // Complete via Identity.verifyMfa with the scoped token.
    const verify = await gql(
      `mutation Verify($input: VerifyMfaInput!) {
        verifyMfa(input: $input) { matched accessToken refreshToken }
      }`,
      {
        input: {
          sessionId: login.sessionId,
          code: authenticator.generate(secret),
        },
      },
      login.mfaToken as string,
    );
    expect(verify.body.errors).toBeUndefined();
    expect(verify.body.data.verifyMfa.matched).toBe('TOTP');
    expect(verify.body.data.verifyMfa.accessToken).toBeTruthy();
    expect(verify.body.data.verifyMfa.refreshToken).toBeTruthy();

    const me = await gql(
      `{ me { email } }`,
      undefined,
      verify.body.data.verifyMfa.accessToken as string,
    );
    expect(me.body.errors).toBeUndefined();
    expect(me.body.data.me.email).toBe(email);
  });

  it('refresh rotates the refresh token and issues a fresh access token', async () => {
    const email = await register('refresh');
    const login = dataOf<{ login: LoginPayload }>(
      await gql(LOGIN_MUTATION, { input: { email, password } }),
    ).login;

    const res = await gql(
      `mutation Refresh($input: RefreshTokenInput!) {
        refresh(input: $input) {
          refreshToken accessToken sessionId userId familyId expiresAt expiresIn
        }
      }`,
      { input: { refreshToken: login.refreshToken } },
    );
    expect(res.body.errors).toBeUndefined();
    const refreshed = dataOf<{ refresh: RefreshPayload }>(res).refresh;
    expect(refreshed.refreshToken).toBeTruthy();
    expect(refreshed.refreshToken).not.toBe(login.refreshToken);
    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.sessionId).toBe(login.sessionId);
    expect(refreshed.userId).toBe(login.userId);
    expect(refreshed.familyId).toBe(login.familyId);
  });

  it('logout revokes the session — a later refresh fails', async () => {
    const email = await register('logout');
    const login = dataOf<{ login: LoginPayload }>(
      await gql(LOGIN_MUTATION, { input: { email, password } }),
    ).login;

    const out = await gql(
      `mutation Logout($input: RefreshTokenInput!) {
        logout(input: $input)
      }`,
      { input: { refreshToken: login.refreshToken } },
    );
    expect(out.body.errors).toBeUndefined();
    expect(out.body.data.logout).toBe(true);

    const reuse = await gql(
      `mutation Refresh($input: RefreshTokenInput!) {
        refresh(input: $input) { refreshToken }
      }`,
      { input: { refreshToken: login.refreshToken } },
    );
    expect(bodyOf<GraphqlErrorBody>(reuse).errors).toBeDefined();
  });

  it('app-credential headers are fail-closed on login', async () => {
    const email = await register('apphdr');

    const partial = await gql(
      LOGIN_MUTATION,
      { input: { email, password } },
      undefined,
      { 'X-Cerberus-App-Id': 'b468a378-0000-0000-0000-000000000000' },
    );
    expect(bodyOf<GraphqlErrorBody>(partial).errors[0].extensions.code).toBe(
      'INPUT_INVALID',
    );

    const bogus = await gql(
      LOGIN_MUTATION,
      { input: { email, password } },
      undefined,
      {
        'X-Cerberus-App-Id': 'b468a378-0000-0000-0000-000000000000',
        'X-Cerberus-App-Secret': 'not-the-secret',
      },
    );
    expect(bodyOf<GraphqlErrorBody>(bogus).errors[0].extensions.code).toBe(
      'UNAUTHENTICATED',
    );
  });
});
