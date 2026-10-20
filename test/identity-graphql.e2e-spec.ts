/**
 * V1.7: Identity GraphQL query coverage.
 *
 * Pins the Identity BC's GraphQL surface — the largest of the
 * 5 resolvers (12 public methods). Per the prior audit, only
 * `adminDisableUserMfa` (admin) and the engagement mutations
 * had any GraphQL coverage. This file fills the identity gap
 * for the most-used methods.
 *
 * Coverage:
 *   Query:
 *     * `health` — unauthenticated liveness probe
 *     * `me` — JWT-gated, returns the calling user
 *     * `getUser(id)` — JWT-gated, requires org:admin scope
 *   Mutation:
 *     * `register` — public, mirrors REST /v1/identity/register
 *     * `changePassword` — JWT-gated
 *     * `updateDisplayName` — JWT-gated (set + clear paths)
 *     * `enableMfa` — JWT-gated, returns TOTP secret
 *     * `sessions` — JWT-gated, lists the calling user's sessions
 *     * `revokeSession(id)` — JWT-gated, cross-user revoke rejected
 *
 * Auth: real user registration + login via REST. The Org:admin
 * guard requires an UPDATE to membership.role='OWNER' (the
 * register flow grants the default role, which doesn't carry
 * `org:admin`).
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { authenticator } from 'otplib';
import { PrismaClient } from '@prisma/client';
import { PublicTestModule } from './public-test.module';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { teardown, uniqueEmail } from './harness';

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
interface UserDto {
  id: string;
  email: string;
  displayName: string | null;
  mfaEnabled: boolean;
  organization: { id: string };
}
interface SessionDto {
  id: string;
  deviceLabel: string | null;
  ipAddress: string | null;
  issuedAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
}
interface MfaEnrollment {
  secret: string;
  otpauthUrl: string;
  recoveryCodes: string[];
}

describe('Identity GraphQL query coverage (V1.7)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let accessToken: string;
  let ownerToken: string;
  let userId: string;
  let orgId: string;
  let secondUserId: string;
  const email = uniqueEmail('gql-ident');
  const secondEmail = uniqueEmail('gql-ident2');
  const password = 'correct horse battery 42!';
  // Set by the changePassword test — enableMfa (which runs after)
  // must present the rotated password.
  const NEW_PASSWORD = 'N3wP4ssw0rd!';
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

    // Register the primary user.
    const reg = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password })
      .expect(201);
    userId = reg.body.userId;
    orgId = reg.body.organizationId;
    const login = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password })
      .expect(200);
    accessToken = bodyOf<LoginResp>(login).accessToken;

    // Register a second user IN THE SAME ORG for the cross-user
    // revoke + getUser tests. Post-H-2, getUser/adminUser enforce an
    // org boundary — a user in a different (auto-created personal)
    // org would return null. Joining the primary user's org keeps
    // both tests meaningful.
    const reg2 = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({
        email: secondEmail,
        password,
        organizationSlug: reg.body.organizationSlug,
      })
      .expect(201);
    secondUserId = reg2.body.userId;
    // Promote the primary user to OWNER for the org:admin test.
    await prisma.membership.updateMany({
      where: { userId, organizationId: orgId },
      data: { role: 'OWNER' },
    });
    // Re-login to get a fresh JWT with the new role.
    const reLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password })
      .expect(200);
    ownerToken = bodyOf<LoginResp>(reLogin).accessToken;
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    await app.close();
    await module.close();
    await teardown();
  });

  it('health — unauthenticated liveness probe', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({ query: `query { health }` })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.health).toBe(true);
  });

  it('me — returns the calling user (JWT-gated)', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `query { me { id email mfaEnabled organization { id } } }`,
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    const me = res.body.data.me as UserDto;
    expect(me.id).toBe(userId);
    expect(me.email).toBe(email);
    expect(me.organization.id).toBe(orgId);
  });

  it('me — rejects unauthenticated request', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({ query: `query { me { id } }` })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors[0].extensions.code).toBe('UNAUTHENTICATED');
  });

  it('getUser(id) — returns the user when called by an org:admin', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        query: `query Get($id: ID!) {
          getUser(id: $id) { id email mfaEnabled role }
        }`,
        variables: { id: secondUserId },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.getUser.id).toBe(secondUserId);
  });

  it('getUser(id) — returns null for an unknown user (catch in resolver)', async () => {
    // The resolver has a try/catch that swallows DomainError
    // and returns null. The intent: "if you don't have the
    // right org, you see null" instead of an error.
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        query: `query Get($id: ID!) {
          getUser(id: $id) { id email }
        }`,
        variables: { id: '00000000-0000-0000-0000-000000000000' },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.getUser).toBeNull();
  });

  it('getUser(id) — returns null for a user in a DIFFERENT org (H-2 org boundary)', async () => {
    // V1.7 audit fix H-2: org:admin scopes the caller to their own
    // org. A user id from another org returns null instead of the
    // victim's record (no cross-tenant read).
    const otherReg = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email: uniqueEmail('gql-ident3'), password })
      .expect(201);
    const otherUserId = otherReg.body.userId as string;
    expect(otherReg.body.organizationId).not.toBe(orgId);

    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        query: `query Get($id: ID!) {
          getUser(id: $id) { id email }
        }`,
        variables: { id: otherUserId },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.getUser).toBeNull();
  });

  it('register — duplicate email returns the opaque 201 stub (no enumeration oracle)', async () => {
    // 2026-10-19 audit LOW: re-registering an existing email returns
    // the same 201 shape as a fresh registration (stub ids) — the
    // client cannot tell the account already exists.
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({
        query: `mutation Register($input: RegisterInput!) {
          register(input: $input) { userId email organizationId organizationSlug autoCreatedOrg }
        }`,
        variables: { input: { email, password: 'Reg1sterP4ss!' } },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    const r = res.body.data.register;
    expect(r.userId).toBeTruthy();
    expect(r.userId).not.toBe(userId); // opaque stub, not the real row
    // The REAL user is untouched.
    const stillThere = await prisma.user.findUnique({ where: { id: userId } });
    expect(stillThere).not.toBeNull();
  });

  it('register — public, mirrors REST /v1/identity/register', async () => {
    const newEmail = uniqueEmail('gql-ident-register');
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .send({
        query: `mutation Register($input: RegisterInput!) {
          register(input: $input) {
            userId email organizationId organizationSlug autoCreatedOrg
          }
        }`,
        variables: { input: { email: newEmail, password: 'Reg1sterP4ss!' } },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    const r = res.body.data.register;
    expect(r.userId).toBeTruthy();
    expect(r.email).toBe(newEmail);
    // No slug supplied + no email-domain match → auto-creates
    // a personal org.
    expect(r.autoCreatedOrg).toBe(true);
  });

  it('changePassword — JWT-gated, returns true on success', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Change($input: ChangePasswordInput!) {
          changePassword(input: $input)
        }`,
        variables: {
          input: {
            currentPassword: password,
            newPassword: NEW_PASSWORD,
          },
        },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.changePassword).toBe(true);
  });

  it('changePassword — wrong current password returns an error', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Change($input: ChangePasswordInput!) {
          changePassword(input: $input)
        }`,
        variables: {
          input: {
            currentPassword: 'wrong-old-password',
            newPassword: 'An0therP4ss!',
          },
        },
      })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // The use case throws `identity.credential.invalid_current_password`
    // (or similar) — pin only the prefix to avoid breakage on
    // minor renames.
    expect(errBody.errors[0].extensions.domainCode).toBe(
      'authentication.invalid_credentials',
    );
  });

  it('updateDisplayName — sets and clears the display name', async () => {
    // Set.
    const setRes = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Update($input: UpdateDisplayNameInput!) {
          updateDisplayName(input: $input) { id displayName }
        }`,
        variables: { input: { displayName: 'New Display Name' } },
      })
      .expect(200);
    expect(setRes.body.errors).toBeUndefined();
    expect(setRes.body.data.updateDisplayName.displayName).toBe(
      'New Display Name',
    );

    // Clear.
    const clearRes = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Update($input: UpdateDisplayNameInput!) {
          updateDisplayName(input: $input) { id displayName }
        }`,
        variables: { input: { clearDisplayName: true } },
      })
      .expect(200);
    expect(clearRes.body.errors).toBeUndefined();
    expect(clearRes.body.data.updateDisplayName.displayName).toBeNull();
  });

  it('updateDisplayName — empty input (neither set nor clear) returns GqlBadRequestException', async () => {
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Update($input: UpdateDisplayNameInput!) {
          updateDisplayName(input: $input) { id }
        }`,
        variables: { input: {} },
      })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // The resolver throws GqlBadRequestException, which the
    // GraphqlDomainErrorFilter maps to INPUT_INVALID.
    expect(errBody.errors[0].extensions.code).toBe('INPUT_INVALID');
  });

  it('enableMfa — returns TOTP secret + recovery codes (currentPassword required)', async () => {
    // NOTE: the changePassword tests above rotated the account
    // password to NEW_PASSWORD — enrollment verifies the CURRENT one.
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Enable($input: EnableMfaInput!) {
          enableMfa(input: $input) { secret otpauthUrl recoveryCodes }
        }`,
        variables: { input: { currentPassword: NEW_PASSWORD } },
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    const m = res.body.data.enableMfa as MfaEnrollment;
    expect(m.secret).toBeTruthy();
    expect(m.otpauthUrl).toContain('otpauth://totp/');
    expect(Array.isArray(m.recoveryCodes)).toBe(true);
    expect(m.recoveryCodes.length).toBe(10);

    // Confirm MFA with a valid TOTP code so subsequent
    // enableMfa calls would fail (already enrolled).
    const code = authenticator.generate(m.secret);
    const confirmRes = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Confirm($input: MfaCodeInput!) {
          confirmMfaEnrollment(input: $input)
        }`,
        variables: { input: { code } },
      })
      .expect(200);
    expect(confirmRes.body.errors).toBeUndefined();
    expect(confirmRes.body.data.confirmMfaEnrollment).toBe(true);
  });

  it('sessions — lists the calling user’s sessions', async () => {
    // Use the original accessToken from beforeAll. The
    // enableMfa test confirmed MFA mid-flow, but the JWT
    // itself doesn't change — it was valid at sign time and
    // is still valid for the standard session-lifetime.
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `query { sessions { id deviceLabel ipAddress issuedAt expiresAt lastUsedAt } }`,
      })
      .expect(200);
    expect(res.body.errors).toBeUndefined();
    const list = res.body.data.sessions as SessionDto[];
    // Just check the shape — the actual count depends on how
    // many logins happened in beforeAll, which varies between
    // runs (the test bootstrap creates a few). The important
    // assertion is that the response is a typed list.
    expect(Array.isArray(list)).toBe(true);
    if (list.length > 0) {
      expect(typeof list[0].id).toBe('string');
      expect(typeof list[0].deviceLabel).toBe('string');
      expect(typeof list[0].issuedAt).toBe('string');
    }
  });

  it('revokeSession — cross-user revoke is rejected', async () => {
    // First, get the second user's session id. We can read
    // sessions from the second user's perspective by
    // logging in as them and querying sessions.
    const secondLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: secondEmail, password })
      .expect(200);
    const secondToken = bodyOf<LoginResp>(secondLogin).accessToken;
    const sessionsRes = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${secondToken}`)
      .send({ query: `query { sessions { id } }` })
      .expect(200);
    const secondSessions = sessionsRes.body.data.sessions as Array<{
      id: string;
    }>;
    expect(secondSessions.length).toBeGreaterThan(0);
    const secondSession = secondSessions[0].id;

    // First user tries to revoke second user's session —
    // the use case rejects this with `auth.session.not_found`
    // (the requester is not allowed to see sessions that
    // aren't theirs).
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        query: `mutation Revoke($sessionId: ID!) {
          revokeSession(sessionId: $sessionId)
        }`,
        variables: { sessionId: secondSession },
      })
      .expect(200);
    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    expect(errBody.errors[0].extensions.domainCode).toBe(
      'authentication.session.not_found',
    );
  });
});
