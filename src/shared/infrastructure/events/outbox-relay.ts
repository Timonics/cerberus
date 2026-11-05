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
 *   - MULTIPLE relay instances may poll the same outbox_events
 *     table (the public and admin Nest apps each boot their own
 *     relay in the same process; horizontally scaled deployments
 *     add more). Rows are claimed atomically with
 *     `FOR UPDATE SKIP LOCKED` inside a short transaction, so two
 *     relays can never pick up the same row. A row claimed but not
 *     processed within CLAIM_STALE_MS (relay crashed mid-tick) is
 *     treated as abandoned and becomes claimable again.
 *   - Single-poll loop per instance. If the previous batch is
 *     still being published when the next tick fires, the next
 *     tick is skipped (we don't queue polls). This is fine for V1 —
 *     event volume is low and a missed tick just delays by 1s.
 *   - The relay marks `processedAt` only after the in-process
 *     publish completes. A crash between publish and mark leaves
 *     the claim to go stale, after which the row is re-published
 *     by some relay — subscribers must be
 *     idempotent (MailSenderDispatcher logs "skipped because
 *     user not found" if the email no longer exists; the
 *     audit-log handler dedupes on `eventName + eventId`).
 *     Delivery is therefore at-least-once.
 *
 * Failure model:
 *   - If the bus publish throws (e.g. unknown eventName from
 *     an outdated subscriber registry), the relay increments
 *     `attempts`, stores `lastError`, and releases the claim so
 *     the next tick retries. After
 *     `MAX_ATTEMPTS_BEFORE_DEAD` failures, the row stays
 *     unprocessed and an operator must intervene.
 *   - Network/DB errors are logged and the row stays unprocessed
 *     — picked up on the next poll.
 */
/**
 * After N failed attempts the row is parked for operator review.
 * Exported so the cleanup cron uses the SAME threshold when purging
 * dead-lettered rows (V1.8 audit fix C3).
 */
export const OUTBOX_MAX_ATTEMPTS_BEFORE_DEAD = 10;

@Injectable()
export class OutboxRelay implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelay.name);
  private running = false;
  private pollHandle: NodeJS.Timeout | null = null;
  // V1.7 audit fix #33: track the in-flight tick so onModuleDestroy
  // can await it. Without this, SIGTERM mid-tick abandons the
  // publish + processedAt update, and the next boot re-publishes
  // the row — causing duplicate audit events (combined with
  // #31's missing dedup constraint). With this, the relay
  // guarantees: when onModuleDestroy resolves, every row that
  // the relay started processing is either fully marked or its
  // failure is recorded.
  private inFlightTick: Promise<void> | null = null;

  /**
   * Set by onModuleDestroy. The `.finally()` re-arm in scheduleNextTick
   * MUST check this: an in-flight tick that resolves after
   * onModuleDestroy cleared the timer would otherwise re-arm the loop
   * forever, ticking against a disconnected Prisma client.
   */
  private stopped = false;

  /** Polling interval. 1s gives a sub-second worst-case latency. */
  private static readonly POLL_INTERVAL_MS = 1_000;

  /** Cap on rows published per tick to keep the loop bounded. */
  private static readonly BATCH_SIZE = 50;

  /**
   * A claimed-but-unprocessed row older than this is treated as
   * abandoned (the relay instance crashed mid-tick) and becomes
   * claimable again. Generous on purpose: publishing a batch takes
   * milliseconds, and onModuleDestroy bounds shutdown at 5s, so 5
   * minutes of silence means the claim owner is genuinely gone.
   */
  private static readonly CLAIM_STALE_MS = 5 * 60_000;

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    @Inject(CLOCK) private readonly clock: Clock,
    private readonly prisma: PrismaService,
  ) {}

  public onModuleInit(): void {
    this.scheduleNextTick();
  }

  public async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    if (this.pollHandle) {
      clearTimeout(this.pollHandle);
      this.pollHandle = null;
    }
    if (this.inFlightTick) {
      // Wait for the in-flight tick to finish. Bound at 5s so a
      // hung publisher doesn't block the process forever.
      await Promise.race([
        this.inFlightTick,
        new Promise((resolve) => setTimeout(resolve, 5_000)),
      ]);
    }
  }

  private scheduleNextTick(): void {
    if (this.pollHandle) clearTimeout(this.pollHandle);
    this.pollHandle = setTimeout(() => {
      // V1.7 audit fix #33: capture the in-flight promise so
      // onModuleDestroy can await it.
      this.inFlightTick = this.tick()
        .catch((err) => {
          this.logger.error(`OutboxRelay tick failed: ${String(err)}`);
        })
        .finally(() => {
          this.inFlightTick = null;
          // Re-arm regardless of success. We DO NOT check
          // `this.running` here — it's set back to false in the
          // tick() finally block, and the previous (buggy) check
          // meant the relay only fired once. We DO check `stopped`
          // so a tick resolving after onModuleDestroy doesn't
          // resurrect the loop against a torn-down Prisma client.
          if (!this.stopped) {
            this.scheduleNextTick();
          }
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
      rows = await this.claimBatch(client);
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
          `OutboxRelay claim failed (will retry next tick): ${message}`,
        );
      }
      return;
    }

    for (const row of rows) {
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
        // row stays claimed; the claim goes stale eventually and
        // the row is retried.
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
              // Release the claim so the next tick retries the row
              // immediately instead of waiting for the stale window.
              claimedAt: null,
            },
          });
        } catch {
          // The update itself can fail if Prisma is mid-disconnect.
          // The row keeps its claim; it goes stale eventually and
          // is retried then.
        }
      }
    }
  }

  /**
   * Atomically claim the next batch of publishable rows.
   *
   * `FOR UPDATE SKIP LOCKED` inside a short transaction is the
   * standard outbox-relay coordination primitive: two relay
   * instances polling the same table (the public + admin apps in
   * one process, or multiple replicas) each lock the rows they
   * will publish, and rows locked by another instance are skipped
   * rather than waited on. The claim is stamped with `claimedAt`
   * so a crashed relay's rows become claimable again once stale.
   *
   * Dead-lettered rows (`attempts` at the max) are excluded from
   * claiming and stay parked for operator review.
   */
  private async claimBatch(client: PrismaClient): Promise<
    Array<{
      id: string;
      payload: unknown;
      attempts: number;
      eventName: string;
    }>
  > {
    const now = this.clock.now();
    const staleBefore = new Date(now.getTime() - OutboxRelay.CLAIM_STALE_MS);
    return client.$transaction(
      async (tx) => {
        const rows = await tx.$queryRaw<
          Array<{
            id: string;
            payload: unknown;
            attempts: number;
            eventName: string;
          }>
        >`
          SELECT "id", "payload", "attempts", "eventName"
          FROM "outbox_events"
          WHERE "processedAt" IS NULL
            AND "attempts" < ${OUTBOX_MAX_ATTEMPTS_BEFORE_DEAD}
            AND ("claimedAt" IS NULL OR "claimedAt" < ${staleBefore})
          ORDER BY "createdAt" ASC
          LIMIT ${OutboxRelay.BATCH_SIZE}
          FOR UPDATE SKIP LOCKED
        `;
        if (rows.length === 0) {
          return rows;
        }
        await tx.outboxEvent.updateMany({
          where: { id: { in: rows.map((r) => r.id) } },
          data: { claimedAt: now },
        });
        return rows;
      },
      // The claim tx touches 50 rows max — a few ms. The cap just
      // keeps a wedged database from pinning the relay forever.
      { timeout: 5_000 },
    );
  }
}
