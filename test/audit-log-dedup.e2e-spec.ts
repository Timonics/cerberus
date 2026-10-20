/**
 * H-10 — audit-log dedup on outbox re-publish.
 *
 * Pins the REAL dedup constraint (`@@unique([eventType, eventId])`,
 * migration 20261019_d1_audit_log_event_id_dedup): when the outbox
 * relay re-publishes an event it already processed (the crash-between-
 * publish-and-mark window), the audit-log handler's insert collides on
 * (eventType, eventId), the P2002 is swallowed, and NO duplicate row
 * lands in audit_logs.
 *
 * The prior constraint (`@@unique([eventType, id])`) was tautological —
 * `id` is the row's own freshly-minted PK — so re-published events
 * silently duplicated every security-audit row. This test would have
 * caught that.
 *
 * Mechanism: the relay marks a row processed only AFTER the in-process
 * publish completes. We simulate the crash window by writing an
 * outbox row directly (the same seam outbox.e2e-spec uses), resetting
 * `processedAt = null` after the first publish, ticking the relay
 * again, and counting audit rows for (eventType, eventId) — must
 * stay 1.
 *
 * Note: no HTTP use-case currently routes `engagement.email_verification.
 * requested` through the outbox (the request use-case publishes
 * in-process after commit), so driving the endpoint would never put
 * the event in the outbox table. The direct insert exercises the same
 * relay → EngagementAuditLogHandler → (eventType, eventId) dedup path.
 */

import { randomUUID } from 'node:crypto';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { OutboxRelay } from '../src/shared/infrastructure/events/outbox-relay';
import { PublicTestModule } from './public-test.module';
import { teardown } from './harness';

describe('H-10 — audit-log dedup on outbox re-publish (integration)', () => {
  let module: TestingModule;
  let app: INestApplication;
  let prisma: PrismaClient;
  let relay: OutboxRelay;

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
    relay = module.get(OutboxRelay);
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await app.close();
    await module.close();
    await teardown();
  });

  it('re-publish through the relay does NOT duplicate the audit row', async () => {
    // 1. Write an outbox row directly (see header) and drive the
    //    relay until it is processed. The outbox table is shared with
    //    every parallel spec, so a fixed tick count can't guarantee
    //    our row is reached — poll instead (cap: 60 ticks).
    const id = randomUUID();
    await prisma.outboxEvent.create({
      data: {
        id,
        eventName: 'engagement.email_verification.requested',
        aggregateType: 'EmailVerification',
        payload: {
          __class: 'EmailVerificationRequested',
          eventId: id,
          eventName: 'engagement.email_verification.requested',
          aggregateType: 'EmailVerification',
          aggregateId: id,
          occurredAt: new Date().toISOString(),
          // The audit-log handler is best-effort and never throws on
          // a missing user (pinned by outbox.e2e-spec).
          userId: '00000000-0000-4000-8000-000000000000',
          verificationId: id,
          plaintextToken: '',
        },
      },
    });

    let row: Awaited<ReturnType<typeof prisma.outboxEvent.findUnique>> = null;
    for (let i = 0; i < 60 && row === null; i++) {
      await relay.tick();
      const candidate = await prisma.outboxEvent.findUnique({
        where: { id },
      });
      if (candidate?.processedAt !== null) {
        row = candidate;
      }
    }
    expect(row).not.toBeNull();
    expect(row!.processedAt).not.toBeNull();
    const eventId = id; // payload.eventId === row id by construction.

    // 2. Exactly one audit row for (eventType, eventId) so far.
    const countBefore = await prisma.auditLog.count({
      where: {
        eventType: 'engagement.email_verification.requested',
        eventId,
      },
    });
    expect(countBefore).toBe(1);

    // 3. Simulate the crash window: the event was published but the
    //    processedAt mark didn't land — the relay re-publishes on a
    //    later tick. Poll until the relay picks OUR row back up.
    await prisma.outboxEvent.update({
      where: { id: row!.id },
      data: { processedAt: null },
    });
    let reprocessed: Awaited<ReturnType<typeof prisma.outboxEvent.findUnique>> =
      null;
    for (let i = 0; i < 60 && reprocessed === null; i++) {
      await relay.tick();
      const candidate = await prisma.outboxEvent.findUnique({
        where: { id: row!.id },
      });
      if (candidate?.processedAt !== null) {
        reprocessed = candidate;
      }
    }
    expect(reprocessed).not.toBeNull();
    expect(reprocessed!.processedAt).not.toBeNull();

    // 4. STILL exactly one audit row — the (eventType, eventId)
    //    unique constraint + the handler's P2002 swallow did their job.
    const countAfter = await prisma.auditLog.count({
      where: {
        eventType: 'engagement.email_verification.requested',
        eventId,
      },
    });
    expect(countAfter).toBe(1);

    // Cleanup.
    await prisma.outboxEvent.delete({ where: { id } });
  }, 60000);
});
