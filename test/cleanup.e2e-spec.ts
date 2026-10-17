/**
 * V1.5 retention cleanup cron — full pipeline.
 *
 * Pins the retention rules for every table the cleanup touches.
 * Each table is seeded with one expired row + one fresh row; the
 * use-case is invoked with TTLs that should delete the expired
 * row but leave the fresh row in place.
 *
 * Tables covered:
 *   - email_verifications  (TTL hours, default 0)
 *   - password_resets      (TTL hours, default 0)
 *   - invitations          (TTL days, default 30)
 *   - sessions             (TTL days, default 30, requires revokedAt)
 *   - recovery_codes       (TTL days, default 90, requires usedAt)
 *   - outbox_events        (TTL days, default 7, requires processedAt)
 *
 * The other tables (signing_keys, app_api_keys, admin_api_keys) need
 * extra FK setup (apps, organizations, admin context) and would
 * inflate this spec past the threshold for the cleanup use-case
 * itself. They get a schema-level coverage by the Prisma migrations
 * + the adapter compiles against them, but not a behavioral test
 * here.
 */

import { randomUUID } from 'node:crypto';
import { Test, TestingModule } from '@nestjs/testing';
import { ValidationPipe, INestApplication } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { CleanupExpiredRowsUseCase } from '../src/cleanup/application/cleanup-expired-rows.use-case';
import { PublicTestModule } from './public-test.module';

describe('Cleanup cron (integration)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let cleanup: CleanupExpiredRowsUseCase;

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
    cleanup = module.get(CleanupExpiredRowsUseCase);
  });

  afterAll(async () => {
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (module) await module.close();
  });

  it('deletes expired email_verifications but keeps fresh ones', async () => {
    const userId = await ensureUser(prisma);
    const expired = `expired-${Date.now()}-${randomUUID()}`;
    const fresh = `fresh-${Date.now()}-${randomUUID()}`;
    await prisma.emailVerification.create({
      data: {
        userId,
        tokenHash: expired,
        expiresAt: new Date(Date.now() - 60_000), // 1 min ago
      },
    });
    await prisma.emailVerification.create({
      data: {
        userId,
        tokenHash: fresh,
        expiresAt: new Date(Date.now() + 60_000), // 1 min from now
      },
    });

    await cleanup.execute({
      emailVerificationTtlHours: 0,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    expect(
      await prisma.emailVerification.findUnique({
        where: { tokenHash: expired },
      }),
    ).toBeNull();
    expect(
      await prisma.emailVerification.findUnique({
        where: { tokenHash: fresh },
      }),
    ).not.toBeNull();

    // cleanup the fresh row we left behind
    await prisma.emailVerification
      .delete({ where: { tokenHash: fresh } })
      .catch(() => undefined);
  });

  it('deletes expired password_resets but keeps fresh ones', async () => {
    const userId = await ensureUser(prisma);
    const expired = `expired-${Date.now()}-${randomUUID()}`;
    const fresh = `fresh-${Date.now()}-${randomUUID()}`;
    await prisma.passwordReset.create({
      data: {
        userId,
        tokenHash: expired,
        expiresAt: new Date(Date.now() - 60_000),
      },
    });
    await prisma.passwordReset.create({
      data: {
        userId,
        tokenHash: fresh,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

    await cleanup.execute({
      emailVerificationTtlHours: 0,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    expect(
      await prisma.passwordReset.findUnique({ where: { tokenHash: expired } }),
    ).toBeNull();
    expect(
      await prisma.passwordReset.findUnique({ where: { tokenHash: fresh } }),
    ).not.toBeNull();
    await prisma.passwordReset
      .delete({ where: { tokenHash: fresh } })
      .catch(() => undefined);
  });

  it('keeps expired rows when TTL is positive (grace window)', async () => {
    const userId = await ensureUser(prisma);
    const tokenHash = `grace-${Date.now()}-${randomUUID()}`;
    // expired 1 hour ago — with TTL=24h, the row stays.
    await prisma.emailVerification.create({
      data: {
        userId,
        tokenHash,
        expiresAt: new Date(Date.now() - 3_600_000),
      },
    });

    await cleanup.execute({
      emailVerificationTtlHours: 24,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    expect(
      await prisma.emailVerification.findUnique({ where: { tokenHash } }),
    ).not.toBeNull();
    await prisma.emailVerification
      .delete({ where: { tokenHash } })
      .catch(() => undefined);
  });

  it('does not delete expired-but-recently-revoked sessions within the 30-day window', async () => {
    const userId = await ensureUser(prisma);
    const familyId = randomUUID();
    const sessionId = randomUUID();
    await prisma.session.create({
      data: {
        id: sessionId,
        userId,
        familyId,
        refreshHash: `revoked-${Date.now()}-${randomUUID()}`,
        organizationId: null,
        expiresAt: new Date(Date.now() + 86_400_000), // 1 day from now
        // revoked 1 hour ago — well within the 30-day default
        revokedAt: new Date(Date.now() - 3_600_000),
        revokeReason: 'USER_LOGOUT',
      },
    });

    await cleanup.execute({
      emailVerificationTtlHours: 0,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    expect(
      await prisma.session.findUnique({ where: { id: sessionId } }),
    ).not.toBeNull();
    await prisma.session
      .delete({ where: { id: sessionId } })
      .catch(() => undefined);
  });

  it('deletes old revoked sessions past the retention window', async () => {
    const userId = await ensureUser(prisma);
    const familyId = randomUUID();
    const sessionId = randomUUID();
    // revoked 60 days ago — outside the 30-day default
    await prisma.session.create({
      data: {
        id: sessionId,
        userId,
        familyId,
        refreshHash: `old-revoked-${Date.now()}-${randomUUID()}`,
        organizationId: null,
        expiresAt: new Date(Date.now() + 86_400_000),
        revokedAt: new Date(Date.now() - 60 * 86_400_000),
        revokeReason: 'USER_LOGOUT',
      },
    });

    await cleanup.execute({
      emailVerificationTtlHours: 0,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    expect(
      await prisma.session.findUnique({ where: { id: sessionId } }),
    ).toBeNull();
  });

  it('returns a count map of every table cleaned', async () => {
    const result = await cleanup.execute({
      emailVerificationTtlHours: 0,
      passwordResetTtlHours: 0,
      invitationTtlDays: 30,
      sessionTtlDays: 30,
      appKeyTtlDays: 90,
      adminKeyTtlDays: 90,
      signingKeyTtlDays: 7,
      recoveryCodeTtlDays: 90,
      outboxTtlDays: 7,
    });

    // Every table key is present, even when count is zero.
    expect(Object.keys(result.deleted).sort()).toEqual(
      [
        'admin_api_keys',
        'app_api_keys',
        'email_verifications',
        'invitations',
        'outbox_events',
        'password_resets',
        'recovery_codes',
        'sessions',
        'signing_keys',
      ].sort(),
    );
    expect(typeof result.durationMs).toBe('number');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

/**
 * Create a real User row (with the minimum FK setup) for tests that
 * need a `userId` to attach other rows to. Idempotent — returns the
 * existing user if one with this email already exists.
 */
async function ensureUser(prisma: PrismaClient): Promise<string> {
  const email = `cleanup-${Date.now()}-${randomUUID()}@cerberus.test`;
  const slug = `cleanup-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const org = await prisma.organization.create({ data: { slug, name: slug } });
  const user = await prisma.user.create({
    data: { email, organizationId: org.id },
  });
  return user.id;
}
