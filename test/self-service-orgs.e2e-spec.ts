/**
 * Self-service org creation + GET /v1/identity/me (HTTP-level).
 *
 * Pins the onboarding flow that closes the "orgs can only be created by
 * operators" gap:
 *
 *   1. GET /v1/identity/me — JWT + auth:read. Returns the caller's
 *      profile (email, org, role, MFA status). 401 without a token.
 *   2. POST /v1/identity/orgs — JWT + auth:write. Creates the org,
 *      makes the caller OWNER, and MOVES the caller's account into it
 *      (V1 is single-org-per-user). 401 without a token; 409 when the
 *      slug is taken or violates slug rules.
 *   3. A colleague can then register with `organizationSlug` set to the
 *      new slug and joins as MEMBER.
 *   4. GraphQL parity: `Identity.createOwnOrganization` mirrors the
 *      REST endpoint.
 *
 * Uses PublicTestModule + supertest against real Postgres, same
 * harness pattern as engagement-graphql.e2e-spec.ts.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { PublicTestModule } from './public-test.module';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { teardown, uniqueEmail } from './harness';

interface LoginResp {
  accessToken: string;
  refreshToken: string;
  mfaRequired: boolean;
}
interface MeResp {
  userId: string;
  organizationId: string;
  email: string;
  displayName: string | null;
  emailVerified: boolean;
  mfaEnabled: boolean;
  role: string;
  createdAt: string;
}
interface RegisterResp {
  userId: string;
  organizationId: string;
  organizationSlug: string;
  email: string;
  autoCreatedOrg: boolean;
}

describe('Self-service orgs + GET /me (HTTP)', () => {
  let module: TestingModule;
  let app: INestApplication;
  const password = 'correct horse battery 42!';
  const bodyOf = <T>(res: { body: unknown }): T => res.body as T;

  const register = async (suffix: string, organizationSlug?: string) => {
    const email = uniqueEmail(`orgs-${suffix}`);
    const res = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email, password, organizationSlug });
    expect(res.status).toBe(201);
    return { email, ...bodyOf<RegisterResp>(res) };
  };

  const login = async (email: string) => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email, password });
    expect(res.status).toBe(200);
    return bodyOf<LoginResp>(res).accessToken;
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
  });

  afterAll(async () => {
    await app.close();
    await module.close();
    await teardown();
  });

  it('GET /me without a token → 401', async () => {
    const res = await request(app.getHttpServer()).get('/v1/identity/me');
    expect(res.status).toBe(401);
  });

  it('GET /me returns the caller profile (email, org, role)', async () => {
    const { email, userId, organizationId } = await register('me-read');
    const token = await login(email);

    const res = await request(app.getHttpServer())
      .get('/v1/identity/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    const me = bodyOf<MeResp>(res);
    expect(me.userId).toBe(userId);
    expect(me.email).toBe(email);
    expect(me.organizationId).toBe(organizationId);
    expect(me.role).toBe('OWNER'); // first user of the personal org
    expect(me.mfaEnabled).toBe(false);
  });

  it('POST /orgs without a token → 401', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .send({ slug: 'no-auth-org', name: 'No Auth Org' });
    expect(res.status).toBe(401);
  });

  it('founder creates an org, becomes OWNER, and their account moves into it', async () => {
    const suffix = Date.now().toString(36);
    const slug = `founder-${suffix}`;
    const { email, organizationId: personalOrgId } = await register('founder');
    const token = await login(email);

    const res = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, name: 'Founder Org', description: 'created by test' });
    expect(res.status).toBe(201);
    expect(res.body.slug).toBe(slug);
    expect(res.body.id).toBeTruthy();
    // A brand-new id — not the personal org.
    expect(res.body.id).not.toBe(personalOrgId);

    const me = bodyOf<MeResp>(
      await request(app.getHttpServer())
        .get('/v1/identity/me')
        .set('Authorization', `Bearer ${token}`),
    );
    expect(me.organizationId).toBe(res.body.id);
    expect(me.role).toBe('OWNER');
  });

  it('duplicate slug → 409 identity.organization.slug_taken', async () => {
    const slug = `dup-${Date.now().toString(36)}`;
    const { email } = await register('dup-a');
    const token = await login(email);
    const first = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, name: 'Dup Org' });
    expect(first.status).toBe(201);

    const { email: email2 } = await register('dup-b');
    const token2 = await login(email2);
    const second = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .set('Authorization', `Bearer ${token2}`)
      .send({ slug, name: 'Dup Org Two' });
    expect(second.status).toBe(409);
    expect(second.body.code).toBe('identity.organization.slug_taken');
  });

  it('reserved slug → 409 domain.invariant_violation', async () => {
    const { email } = await register('reserved');
    const token = await login(email);
    const res = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug: 'admin', name: 'Shadow Admin' });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('domain.invariant_violation');
  });

  it('colleague registers with the new slug and joins as MEMBER', async () => {
    const slug = `team-${Date.now().toString(36)}`;
    const { email: founderEmail } = await register('team-founder');
    const founderToken = await login(founderEmail);
    const org = await request(app.getHttpServer())
      .post('/v1/identity/orgs')
      .set('Authorization', `Bearer ${founderToken}`)
      .send({ slug, name: 'Team Org' });
    expect(org.status).toBe(201);

    // Colleague registers against the slug — joins the SAME org.
    const { email, autoCreatedOrg, organizationId } = await register(
      'team-member',
      slug,
    );
    expect(autoCreatedOrg).toBe(false);
    expect(organizationId).toBe(org.body.id);

    const token = await login(email);
    const me = bodyOf<MeResp>(
      await request(app.getHttpServer())
        .get('/v1/identity/me')
        .set('Authorization', `Bearer ${token}`),
    );
    expect(me.organizationId).toBe(org.body.id);
    expect(me.role).toBe('MEMBER');
  });

  it('GraphQL createOwnOrganization mirrors the REST endpoint', async () => {
    const slug = `gql-${Date.now().toString(36)}`;
    const { email } = await register('gql-founder');
    const token = await login(email);

    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${token}`)
      .send({
        query: `mutation Create($input: CreateOwnOrganizationInput!) {
          createOwnOrganization(input: $input) { id slug name }
        }`,
        variables: { input: { slug, name: 'GQL Org' } },
      });
    expect(res.status).toBe(200);
    expect(res.body.errors).toBeUndefined();
    expect(res.body.data.createOwnOrganization.slug).toBe(slug);
    expect(res.body.data.createOwnOrganization.name).toBe('GQL Org');
  });
});
