import {
  Inject,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../../config/configuration';
import { CleanupExpiredRowsUseCase } from './cleanup-expired-rows.use-case';

/**
 * Drives the cleanup use-case on a recurring schedule.
 *
 * V1.5 has two recurring jobs: this cleanup cron and the outbox
 * relay (`OutboxRelay`). Both use the same pattern — a self-rescheduling
 * `setTimeout` that doesn't keep the Node process alive (`.unref()`).
 * We deliberately do NOT use `@nestjs/schedule`:
 *
 *   - Avoids pulling in another dependency for a single cron.
 *   - Matches the relay's lifecycle (init/destroy), which keeps
 *     the operational story consistent.
 *   - Lets the schedule be runtime-driven from config (`schedule`).
 *
 * Schedule syntax: standard 5-field cron (`m h d M w`). We compute
 * the next firing date on every tick so a server restart resets
 * the clock without drift. A `setTimeout` of `next - now` ms is
 * the natural fit.
 *
 * Disabling: set `CLEANUP_SCHEDULE=''` (the env validator allows
 * empty). The scheduler logs once and skips all ticks.
 */
@Injectable()
export class CleanupScheduler implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(CleanupScheduler.name);

  /** When non-null, a `setTimeout` handle is pending the next fire. */
  private timer: NodeJS.Timeout | null = null;

  /** Set to true on `OnModuleDestroy` so the in-flight tick finishes cleanly. */
  private stopped = false;

  public constructor(
    private readonly cleanup: CleanupExpiredRowsUseCase,
    @Inject(ConfigService) private readonly config: ConfigService,
  ) {}

  public onModuleInit(): void {
    const schedule =
      this.config.getOrThrow<AppConfig['cleanup']>('cleanup').schedule;
    if (!schedule) {
      this.logger.warn('CLEANUP_SCHEDULE is empty — cleanup cron disabled');
      return;
    }
    this.logger.log(`cleanup cron registered with schedule "${schedule}"`);
    this.scheduleNextTick(schedule);
  }

  public onModuleDestroy(): void {
    this.stopped = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /**
   * Manually trigger a cleanup pass. Exposed for ops endpoints +
   * integration tests that don't want to wait for the cron.
   */
  public async runNow(): Promise<void> {
    const ttls = this.config.getOrThrow<AppConfig['cleanup']>('cleanup');
    // Strip the `schedule` field — the use-case only consumes TTLs.
    const { schedule, ...ttlOnly } = ttls;
    void schedule;
    await this.cleanup.execute(ttlOnly);
  }

  private scheduleNextTick(schedule: string): void {
    if (this.stopped) return;
    const ms = msUntilNext(schedule);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.tick(schedule);
    }, ms);
    // Don't keep the process alive on teardown.
    this.timer.unref();
  }

  private async tick(schedule: string): Promise<void> {
    if (this.stopped) return;
    try {
      await this.runNow();
    } catch (err) {
      this.logger.error('cleanup pass error', err as Error);
    } finally {
      // Re-arm unconditionally. The `running` flag's job is to
      // prevent overlapping ticks (skipped here — the use-case
      // is awaited to completion), not to gate re-arming.
      this.scheduleNextTick(schedule);
    }
  }
}

/**
 * Parse a 5-field cron expression and return the number of
 * milliseconds until the next firing date. Pure function, no
 * timezone awareness (server-local).
 *
 * Supported subset:
 *   - "*" in any field
 *   - numeric literal in any field
 *   - comma-separated lists (e.g. "0,30")
 *   - ranges (e.g. "1-5")
 *
 * Anything outside this subset throws — fail loud, fail early.
 */
export function msUntilNext(expr: string, now: Date = new Date()): number {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(
      `cleanup cron: expected 5 fields, got ${fields.length}: "${expr}"`,
    );
  }
  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields;

  // Walk forward in 1-minute steps until we find a match. The cron
  // schedules we use fire at most once per hour, so the worst-case
  // walk is bounded (and the schedule is recomputed only when the
  // server starts or we miss a fire).
  const candidate = new Date(now.getTime());
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  // Bound the walk to 366 days; an unmatchable schedule would loop
  // forever otherwise. Real cron expressions always match within
  // a year — if we don't find one in 366 days, the schedule is
  // pathological.
  const limit = candidate.getTime() + 366 * 86_400_000;
  while (candidate.getTime() < limit) {
    if (
      matchField(minute, candidate.getMinutes()) &&
      matchField(hour, candidate.getHours()) &&
      matchField(dayOfMonth, candidate.getDate()) &&
      matchField(month, candidate.getMonth() + 1) &&
      matchField(dayOfWeek, candidate.getDay())
    ) {
      return candidate.getTime() - now.getTime();
    }
    candidate.setMinutes(candidate.getMinutes() + 1);
  }
  throw new Error(`cleanup cron: no match found within 366 days for "${expr}"`);
}

function matchField(spec: string, value: number): boolean {
  for (const part of spec.split(',')) {
    if (part === '*') return true;
    const rangeMatch = /^(\d+)-(\d+)$/.exec(part);
    if (rangeMatch) {
      const [, lo, hi] = rangeMatch;
      if (value >= Number(lo) && value <= Number(hi)) return true;
      continue;
    }
    if (Number(part) === value) return true;
  }
  return false;
}
