/**
 * Admin audit search — `from`/`to` SQL filter.
 *
 * Pins the V1.5 fix: the use-case validates from/to, and now the
 * Prisma repo actually narrows the result set on those values.
 * Pre-V1.5: the repo ignored the range and every search returned
 * unfiltered rows.
 *
 * We use a unique random userId per test run so the seeded rows
 * don't collide with the audit rows the search use-case itself
 * creates (admin.audit.searched uses query.userId as its userId).
 */

import { randomUUID } from 'node:crypto';
import { RecordAuditEventUseCase } from '../src/engagement/application/use-cases/record-audit-event.use-case';
import { AdminSearchAuditLogUseCase } from '../src/administration/application/use-cases/admin-search-audit-log.use-case';
import { PrismaClient } from '@prisma/client';
import { Test, TestingModule } from '@nestjs/testing';
import { PublicTestModule } from './public-test.module';
import { teardown } from './harness';

describe('Admin audit search — from/to time range (integration)', () => {
  let module: TestingModule;
  let prisma: PrismaClient;
  let searchUc: AdminSearchAuditLogUseCase;
  let recordAudit: RecordAuditEventUseCase;
  const userId = randomUUID();

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [PublicTestModule],
    }).compile();
    prisma = new PrismaClient();
    await prisma.$connect();
    searchUc = module.get(AdminSearchAuditLogUseCase);
    recordAudit = module.get(RecordAuditEventUseCase);
  });

  afterAll(async () => {
    // Clean up any rows we seeded.
    await prisma.auditLog.deleteMany({ where: { userId } });
    await prisma.$disconnect();
    await module.close();
    await teardown();
  });

  it('filters rows by the from/to window', async () => {
    // Seed 5 audit rows at known timestamps.
    const t1 = new Date('2026-01-01T00:00:00Z');
    const t2 = new Date('2026-02-01T00:00:00Z');
    const t3 = new Date('2026-03-01T00:00:00Z');
    const t4 = new Date('2026-04-01T00:00:00Z');
    const t5 = new Date('2026-05-01T00:00:00Z');

    for (const t of [t1, t2, t3, t4, t5]) {
      await prisma.auditLog.create({
        data: {
          id: randomUUID(),
          userId,
          eventType: 'authentication.login.succeeded',
          payload: { test: true },
          createdAt: t,
        },
      });
    }
    // Sanity: verify we seeded exactly 5 rows for this userId.
    const seeded = await prisma.auditLog.count({ where: { userId } });

    console.log('seeded for userId', userId, '=', seeded);
    expect(seeded).toBe(5);

    // Note: each searchUc.execute() call writes an `admin.audit.searched`
    // row whose `userId` mirrors the search's userId. Each of those
    // rows has `createdAt = now`, so it falls in the from-window.
    // We count only the seeded rows by matching `eventType`.
    function countSeeded(rows: ReadonlyArray<{ eventType: string }>): number {
      return rows.filter(
        (r) => r.eventType === 'authentication.login.succeeded',
      ).length;
    }

    // Window: only Feb + Mar + Apr seeded rows.
    const result = await searchUc.execute({
      userId,
      from: new Date('2026-02-01T00:00:00Z'),
      to: new Date('2026-04-30T23:59:59Z'),
      limit: 100,
    });
    expect(countSeeded(result.entries)).toBe(3);

    // from-only window: 4 seeded rows (Jan 1 excluded).
    const fromOnly = await searchUc.execute({
      userId,
      from: new Date('2026-01-15T00:00:00Z'),
      limit: 100,
    });
    expect(countSeeded(fromOnly.entries)).toBe(4);

    // to-only window: only t1 seeded row.
    const toOnly = await searchUc.execute({
      userId,
      to: new Date('2026-01-31T23:59:59Z'),
      limit: 100,
    });
    expect(countSeeded(toOnly.entries)).toBe(1);
    expect(toOnly.entries[0].createdAt.toISOString()).toBe(t1.toISOString());

    // No range → all 5 seeded rows.
    const noRange = await searchUc.execute({
      userId,
      limit: 100,
    });
    expect(countSeeded(noRange.entries)).toBe(5);

    void recordAudit;
  });

  it('applies offset as SQL SKIP (paginates)', async () => {
    // Seed 5 rows at distinct timestamps. They must sort STRICTLY
    // AHEAD of every other row for this userId — including the
    // `admin.audit.searched` rows each searchUc.execute() writes with
    // createdAt = now. Seeding at past timestamps lets those
    // interleaved rows into the first page between the two page
    // requests and shifts the window (overlap). Future timestamps
    // keep the seeded rows pinned to the top of the desc ordering.
    const base = Date.now() + 60_000;
    for (let i = 0; i < 5; i++) {
      await prisma.auditLog.create({
        data: {
          id: randomUUID(),
          userId,
          eventType: 'authentication.login.succeeded',
          payload: { test: true, seq: i },
          createdAt: new Date(base + i * 60_000),
        },
      });
    }
    const page1 = await searchUc.execute({ userId, limit: 2, offset: 0 });
    const page2 = await searchUc.execute({ userId, limit: 2, offset: 2 });
    expect(page1.entries.length).toBe(2);
    expect(page2.entries.length).toBe(2);
    // No overlap between pages.
    const ids1 = new Set(page1.entries.map((e) => e.id));
    for (const e of page2.entries) {
      expect(ids1.has(e.id)).toBe(false);
    }
  });

  it('rejects an inverted from/to range (400-class domain error)', async () => {
    await expect(
      searchUc.execute({
        userId,
        from: new Date('2026-05-01T00:00:00Z'),
        to: new Date('2026-01-01T00:00:00Z'),
        limit: 10,
      }),
    ).rejects.toMatchObject({
      code: 'admin.audit.search.invalid_range',
    });
  });

  it('records callerKeyId on the admin.audit.searched row', async () => {
    const callerKeyId = randomUUID();
    await searchUc.execute({
      userId,
      limit: 5,
      callerUserId: null,
      callerKeyId,
    });
    const searched = await prisma.auditLog.findFirst({
      where: {
        eventType: 'admin.audit.searched',
        payload: { path: ['callerKeyId'], equals: callerKeyId },
      },
      orderBy: { createdAt: 'desc' },
    });
    expect(searched).not.toBeNull();
    expect((searched!.payload as { callerKeyId: string }).callerKeyId).toBe(
      callerKeyId,
    );
  });
});
