/**
 * C-1 — Cross-tenant IDOR via org:admin GraphQL scope.
 *
 * End-to-end test through the public HTTP listener. Exercises:
 *   - AuthGuard({ requireOrgAdmin: true }) scope check
 *   - CurrentUser() GraphQL context population from JWT
 *   - GraphqlDomainErrorFilter mapping DomainError → extensions.code
 *   - AdminDisableUserMfaUseCase (the org-match check is in here)
 *
 * The pure-domain spec covers the aggregate behavior. This test
 * pins the integration: that the membership lookup + org comparison
 * + Repo writes all wire together correctly, AND that the GraphQL
 * filter actually surfaces the right error code to the attacker.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { authenticator } from 'otplib';
import { PublicTestModule } from './public-test.module';
import { GraphqlDomainErrorFilter } from '../src/graphql/graphql-domain-error.filter';
import { teardown, uniqueEmail } from './harness';

describe('C-1 — cross-tenant IDOR (HTTP)', () => {
  let app: INestApplication;
  let module: TestingModule;

  // Typed accessor for supertest response.body. Casting through
  // `unknown` keeps the type checker happy without sprinkling
  // // eslint-disable comments.
  const bodyOf = <T>(res: { body: unknown }): T => res.body as T;

  interface RegisterResp {
    userId: string;
    organizationId: string;
  }
  interface LoginResp {
    accessToken: string;
    refreshToken: string;
    mfaRequired: boolean;
  }
  interface EnableResp {
    secret: string;
  }
  interface GraphqlErrorBody {
    errors: Array<{
      message: string;
      extensions: { code: string; domainCode?: string };
    }>;
  }
  interface GraphqlSuccessBody<T> {
    data?: T;
    errors?: unknown;
  }
  interface AdminDisablePayload {
    adminDisableUserMfa: { userId: string };
  }

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
    // Mirror the production public-app.ts setup: register the
    // GraphQL filter as a global filter so DomainErrors thrown
    // from resolvers surface with extensions.code instead of being
    // wrapped in INTERNAL_SERVER_ERROR. (See commit d7546b3.)
    app.useGlobalFilters(new GraphqlDomainErrorFilter());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    await module.close();
    await teardown();
  });

  it('attacker in org A cannot disable MFA on victim in org B via GraphQL', async () => {
    const password = 'correct horse battery staple 1!';
    const attackerEmail = uniqueEmail('c1-httpa');
    const victimEmail = uniqueEmail('c1-httpv');

    const registerAttacker = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email: attackerEmail, password })
      .expect(201);
    const attackerReg = bodyOf<RegisterResp>(registerAttacker);

    const attackerLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: attackerEmail, password })
      .expect(200);
    const attackerAccess = bodyOf<LoginResp>(attackerLogin).accessToken;

    const registerVictim = await request(app.getHttpServer())
      .post('/v1/identity/register')
      .send({ email: victimEmail, password })
      .expect(201);
    const victimReg = bodyOf<RegisterResp>(registerVictim);
    const victimUserId = victimReg.userId;
    const victimLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: victimEmail, password })
      .expect(200);
    const victimAccess = bodyOf<LoginResp>(victimLogin).accessToken;

    // Sanity: distinct orgs.
    expect(attackerReg.organizationId).not.toBe(victimReg.organizationId);

    // Victim enables + confirms MFA so AdminDisableUserMfa has
    // something to disable (the use-case throws 404 if no MFA row).
    const enableResult = await request(app.getHttpServer())
      .post('/v1/identity/mfa/enable')
      .set('Authorization', `Bearer ${victimAccess}`)
      .send({})
      .expect(200);
    const code = authenticator.generate(
      bodyOf<EnableResp>(enableResult).secret,
    );
    await request(app.getHttpServer())
      .post('/v1/identity/mfa/confirm')
      .set('Authorization', `Bearer ${victimAccess}`)
      .send({ code })
      .expect(204);

    // === THE ATTACK ===
    // Attacker hits the GraphQL mutation. The audit-fix says:
    //   - AuthGuard({ requireOrgAdmin: true }) accepts the call
    //     because attacker has org:admin scope (for their own org).
    //   - AdminDisableUserMfaUseCase resolves attacker's org from
    //     membership, compares to victim's org, throws admin.forbidden.
    //   - GraphqlDomainErrorFilter surfaces the code in extensions.code.
    const mutation = `
      mutation Disable($input: AdminDisableUserMfaInput!) {
        adminDisableUserMfa(input: $input) { userId }
      }
    `;
    const res = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${attackerAccess}`)
      .send({
        query: mutation,
        variables: {
          input: {
            userId: victimUserId,
            adminKeyId: null,
            reason: 'cross-tenant attack',
          },
        },
      })
      .expect(200);

    const errBody = bodyOf<GraphqlErrorBody>(res);
    expect(errBody.errors).toBeDefined();
    // The GraphqlDomainErrorFilter maps admin.forbidden to FORBIDDEN
    // graphql code, plus the domainCode surfaces too.
    expect(errBody.errors[0].extensions.code).toBe('FORBIDDEN');
    expect(errBody.errors[0].extensions.domainCode).toBe('admin.forbidden');
    expect(errBody.errors[0].message).toContain('outside your organization');

    // === DEFENSE VERIFIED ===
    // Victim's MFA is still intact. Login requires mfaRequired=true.
    const reLogin = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: victimEmail, password })
      .expect(200);
    expect(bodyOf<LoginResp>(reLogin).mfaRequired).toBe(true);

    // === POSITIVE PATH ===
    // Victim (in their own org) CAN disable their own MFA via the
    // same mutation. This proves the guard isn't over-restrictive.
    const victimSelfDisable = await request(app.getHttpServer())
      .post('/graphql')
      .set('Authorization', `Bearer ${victimAccess}`)
      .send({
        query: mutation,
        variables: {
          input: {
            userId: victimUserId,
            adminKeyId: null,
            reason: 'self-test',
          },
        },
      })
      .expect(200);
    const successBody =
      bodyOf<GraphqlSuccessBody<AdminDisablePayload>>(victimSelfDisable);
    expect(successBody.data).toBeDefined();
    expect(successBody.data?.adminDisableUserMfa.userId).toBe(victimUserId);
    expect(successBody.errors).toBeUndefined();
  }, 60000);
});
