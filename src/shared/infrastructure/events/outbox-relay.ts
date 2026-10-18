import {
  Inject,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { CLOCK, Clock } from '../../domain/clock/clock.port';
import { EVENT_BUS, EventBus } from '../../domain/events/event-bus.port';
import { PrismaService } from '../../../prisma/prisma.service';
import { rehydrateEvent } from './rehydrate-event';

/**
 * V1.5: Transactional outbox relay.
 *
 * Polls the `outbox_events` table for unprocessed rows, rehydrates
 * each event class from the stored payload, and re-publishes via
 * the in-process `EventBus`. Subscribers (MailSenderDispatcher,
 * EngagementAuditLogHandler, etc.) consume as if the event had
 * fired in real time.
 *
 * Concurrency model:
 *   - One relay per Nest process. The CI starter has both public
 *     and admin listeners — they share the same `OutboxRelay`
 *     singleton from SharedKernelModule.
 *   - Single-poll loop. If the previous batch is still being
 *     published when the next tick fires, the next tick is skipped
 *     (we don't queue polls). This is fine for V1 — event
 *     volume is low and a missed tick just delays by 1s.
 *   - The relay marks `processedAt` only after the in-process
 *     publish completes. A crash between publish and mark causes
 *     a re-publish on the next boot — subscribers must be
 *     idempotent (MailSenderDispatcher logs "skipped because
 *     user not found" if the email no longer exists; the
 *     audit-log handler dedupes on `eventName + eventId`).
 *
 * Failure model:
 *   - If the bus publish throws (e.g. unknown eventName from
 *     an outdated subscriber registry), the relay increments
 *     `attempts` and stores `lastError`. After
 *     `MAX_ATTEMPTS_BEFORE_DEAD` failures, the row stays
 *     unprocessed and an operator must intervene.
 *   - Network/DB errors are logged and the row stays unprocessed
 *     — picked up on the next poll.
 */
@Injectable()
export class OutboxRelay implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelay.name);
  private running = false;
  private pollHandle: NodeJS.Timeout | null = null;

  /** Polling interval. 1s gives a sub-second worst-case latency. */
  private static readonly POLL_INTERVAL_MS = 1_000;

  /** After N failed attempts the row is parked for operator review. */
  private static readonly MAX_ATTEMPTS_BEFORE_DEAD = 10;

  /** Cap on rows published per tick to keep the loop bounded. */
  private static readonly BATCH_SIZE = 50;

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    @Inject(CLOCK) private readonly clock: Clock,
    private readonly prisma: PrismaService,
  ) {}

  public onModuleInit(): void {
    this.scheduleNextTick();
  }

  public onModuleDestroy(): void {
    if (this.pollHandle) {
      clearTimeout(this.pollHandle);
      this.pollHandle = null;
    }
  }

  private scheduleNextTick(): void {
    if (this.pollHandle) clearTimeout(this.pollHandle);
    this.pollHandle = setTimeout(() => {
      this.tick()
        .catch((err) => {
          this.logger.error(`OutboxRelay tick failed: ${String(err)}`);
        })
        .finally(() => {
          // Re-arm regardless of success. We DO NOT check
          // `this.running` here — it's set back to false in the
          // tick() finally block, and the previous (buggy) check
          // meant the relay only fired once.
          this.scheduleNextTick();
        });
    }, OutboxRelay.POLL_INTERVAL_MS);
    // Don't keep the Node process alive just for the relay —
    // important for tests (jest teardown) and graceful shutdown
    // of long-lived processes.
    if (typeof this.pollHandle.unref === 'function') {
      this.pollHandle.unref();
    }
  }

  /**
   * Public so integration tests can drive the relay synchronously.
   */
  public async tick(): Promise<void> {
    if (this.running) {
      // Skip — the previous tick is still running. This is a
      // single-threaded Node, so a "still running" can only mean
      // the previous await is pending; we just skip and re-arm.
      return;
    }
    this.running = true;
    try {
      await this.publishOnce();
    } finally {
      this.running = false;
    }
  }

  private async publishOnce(): Promise<void> {
    const client = this.prisma as PrismaClient;
    let rows: Array<{
      id: string;
      payload: unknown;
      attempts: number;
      eventName: string;
    }>;
    try {
      rows = await client.outboxEvent.findMany({
        where: { processedAt: null },
        orderBy: { createdAt: 'asc' },
        take: OutboxRelay.BATCH_SIZE,
      });
    } catch (err) {
      // V1.7: Prisma engine may be in the middle of disconnecting
      // (e.g. jest teardown of a sibling test's Nest app on a
      // different port can race the relay's tick). The error
      // "Engine is not yet connected" is transient — silently
      // skip the tick and try again on the next poll. We do NOT
      // re-throw because the relay runs on a 1s loop and the
      // next tick will succeed once the Prisma client is
      // re-initialized (in a stable process) or fully shut down
      // (in tests, the loop is `.unref()`d so it won't keep
      // the Node process alive past teardown).
      const message = err instanceof Error ? err.message : String(err);
      if (
        !/Engine is not (yet )?connected|Engine has been closed/i.test(message)
      ) {
        // An unknown error is still worth surfacing — log at warn
        // so it shows up in Sentry/stdout but doesn't kill the
        // test runner.
        this.logger.warn(
          `OutboxRelay poll failed (will retry next tick): ${message}`,
        );
      }
      return;
    }

    for (const row of rows) {
      if (row.attempts >= OutboxRelay.MAX_ATTEMPTS_BEFORE_DEAD) {
        // Parked — operator must reset `attempts` to retry.
        continue;
      }
      try {
        const event = rehydrateEvent(
          row.payload as Parameters<typeof rehydrateEvent>[0],
        );
        await this.bus.publish(event);
        await client.outboxEvent.update({
          where: { id: row.id },
          data: { processedAt: this.clock.now() },
        });
      } catch (err) {
        // V1.7: same as the rows-from-db block — silently skip
        // if Prisma is mid-disconnect during test teardown. The
        // row stays unprocessed; the next tick (or operator
        // reset of `attempts`) retries it.
        const message = err instanceof Error ? err.message : String(err);
        if (
          /Engine is not (yet )?connected|Engine has been closed/i.test(message)
        ) {
          return;
        }
        this.logger.warn(
          `OutboxRelay failed to publish event ${row.id} (${row.eventName}) attempt=${row.attempts + 1}: ${message}`,
        );
        try {
          await client.outboxEvent.update({
            where: { id: row.id },
            data: {
              attempts: row.attempts + 1,
              lastError: message.slice(0, 500),
            },
          });
        } catch {
          // The update itself can fail if Prisma is mid-disconnect.
          // The row stays with its old `attempts` count; the next
          // tick (if Prisma recovers) retries.
        }
      }
    }
  }
}
