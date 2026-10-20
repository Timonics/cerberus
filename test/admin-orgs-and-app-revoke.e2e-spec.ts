/**
 * Admin org creation + app key auto-revoke.
 *
 * Two P1 audit items in one test:
 *   1. POST /admin/orgs creates an empty organization that users
 *      can later register with.
 *   2. Rotating an app's API key auto-revokes the previous key —
 *      the old key row gets `revokedAt` set, and verifying the old
 *      key fails.
 *
 * Requires a seeded admin API key. We create one in beforeAll by
 * calling the use-case directly (the controller path would require
 * a real IP-allowlisted request, which is overkill for an integration
 * test).
 */

import { CreateOrganizationUseCase } from '../src/identity/application/use-cases/create-organization.use-case';
import { RotateAppApiKeyUseCase } from '../src/apps/application/use-cases/rotate-app-api-key.use-case';
import { RegisterAppUseCase } from '../src/apps/application/use-cases/register-app.use-case';
import { VerifyAppApiKeyUseCase } from '../src/apps/application/use-cases/verify-app-api-key.use-case';
import { PrismaClient } from '@prisma/client';
import { buildIntegrationContext, teardown } from './harness';

describe('Admin org creation + app key auto-revoke (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let prisma: PrismaClient;
  let createOrg: CreateOrganizationUseCase;
  let registerApp: RegisterAppUseCase;
  let rotateKey: RotateAppApiKeyUseCase;
  let verifyKey: VerifyAppApiKeyUseCase;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    prisma = new PrismaClient();
    await prisma.$connect();
    createOrg = ctx.get(CreateOrganizationUseCase);
    registerApp = ctx.get(RegisterAppUseCase);
    rotateKey = ctx.get(RotateAppApiKeyUseCase);
    verifyKey = ctx.get(VerifyAppApiKeyUseCase);
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await ctx.close();
    await teardown();
  });

  describe('POST /admin/orgs', () => {
    it('creates an empty organization with a fresh slug', async () => {
      const slug = `acme-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
      const result = await createOrg.execute({
        slug,
        name: 'Acme Corp',
        description: 'Test organization',
      });
      expect(result.organization.slug.value).toBe(slug);
      expect(result.organization.name).toBe('Acme Corp');

      // Audit row written.
      const audit = await prisma.auditLog.findFirst({
        where: {
          eventType: 'admin.organization.created',
          payload: { path: ['slug'], equals: slug },
        },
      });
      expect(audit).not.toBeNull();
    });

    it('rejects a duplicate slug', async () => {
      const slug = `dup-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
      await createOrg.execute({ slug, name: 'First', description: null });
      await expect(
        createOrg.execute({ slug, name: 'Second', description: null }),
      ).rejects.toMatchObject({ code: 'identity.organization.slug_taken' });
    });

    it('rejects a reserved slug (admin, api, etc.)', async () => {
      await expect(
        createOrg.execute({
          slug: 'admin',
          name: 'Hacker',
          description: null,
        }),
      ).rejects.toMatchObject({ code: 'domain.invariant_violation' });
    });

    it('rejects a too-long name', async () => {
      const longName = 'A'.repeat(200);
      await expect(
        createOrg.execute({
          slug: `long-${Date.now()}`,
          name: longName,
          description: null,
        }),
      ).rejects.toMatchObject({
        code: 'identity.organization.name_too_long',
      });
    });
  });

  describe('App key auto-revoke on rotate', () => {
    it('auto-revokes the previous key when a new one is minted', async () => {
      // Register an app.
      const appResult = await registerApp.execute({
        name: `revoke-test-${Date.now()}`,
        description: null,
        defaultOrgSlug: null,
        contactEmail: 'app-test@cerberus.local',
        ttlSeconds: 3600,
      });
      const oldPlaintext = appResult.plaintextApiKey;

      // Capture the existing api_keys row count for this app. The
      // rotate step will create a new row AND revoke the old one.
      const beforeRows = await prisma.appApiKey.count({
        where: { appId: appResult.app.id },
      });

      // Verify the original key works.
      const verified1 = await verifyKey.execute({
        appId: appResult.app.id,
        plaintextApiKey: oldPlaintext,
      });
      expect(verified1).not.toBeNull();
      expect(verified1!.appId).toBe(appResult.app.id);

      // Rotate.
      const rotated = await rotateKey.execute(appResult.app.id, 3600);
      const newPlaintext = rotated.plaintextApiKey;
      expect(newPlaintext).not.toBe(oldPlaintext);

      // There should now be 2 rows: the new (active) and the old
      // (revoked). The audit event stores the previousKeyId so we
      // can find the old row.
      const afterRows = await prisma.appApiKey.count({
        where: { appId: appResult.app.id },
      });
      expect(afterRows).toBe(beforeRows + 1);

      const audit = await prisma.auditLog.findFirst({
        where: {
          eventType: 'apps.app.key_rotated',
          payload: { path: ['appId'], equals: appResult.app.id },
        },
        orderBy: { createdAt: 'desc' },
      });
      const payload = audit?.payload as { previousKeyId: string | null };
      expect(payload.previousKeyId).not.toBeNull();

      const oldRow = await prisma.appApiKey.findUnique({
        where: { id: payload.previousKeyId! },
      });
      expect(oldRow).not.toBeNull();
      expect(oldRow?.revokedAt).not.toBeNull();

      // Verifying the OLD key now throws — V1.7 uniform credential
      // code (the distinct app.api_key.invalid was an oracle).
      await expect(
        verifyKey.execute({
          appId: appResult.app.id,
          plaintextApiKey: oldPlaintext,
        }),
      ).rejects.toMatchObject({ code: 'app.credentials.invalid' });

      // Verifying the NEW key still works.
      const verified3 = await verifyKey.execute({
        appId: appResult.app.id,
        plaintextApiKey: newPlaintext,
      });
      expect(verified3).not.toBeNull();
      expect(verified3!.appId).toBe(appResult.app.id);
    });

    it('records previousKeyId in the rotation audit row', async () => {
      const appResult = await registerApp.execute({
        name: `audit-test-${Date.now()}`,
        description: null,
        defaultOrgSlug: null,
        contactEmail: 'app-audit@cerberus.local',
        ttlSeconds: 3600,
      });
      await rotateKey.execute(appResult.app.id, 3600);

      const audit = await prisma.auditLog.findFirst({
        where: {
          eventType: 'apps.app.key_rotated',
          payload: { path: ['appId'], equals: appResult.app.id },
        },
        orderBy: { createdAt: 'desc' },
      });
      expect(audit).not.toBeNull();
      const payload = audit?.payload as { previousKeyId: string | null };
      expect(payload.previousKeyId).not.toBeNull();

      // The previous key row should match the previousKeyId AND
      // have revokedAt set (V1.5 auto-revoke).
      const oldRow = await prisma.appApiKey.findUnique({
        where: { id: payload.previousKeyId! },
      });
      expect(oldRow).not.toBeNull();
      expect(oldRow?.revokedAt).not.toBeNull();
    });
  });
});
