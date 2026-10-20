import { Tx } from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { AuditLog } from '../aggregates/audit-log';
import { AuditEventType } from '../value-objects/audit-event-type';

/**
 * Optional time-range filter. `from` is inclusive, `to` is inclusive.
 * V1.5: previously these were validated by the use-case but
 * ignored at SQL — every search ran unfiltered. Now they pass
 * through to Postgres.
 */
export interface AuditLogTimeRange {
  from?: Date | null;
  to?: Date | null;
}

export abstract class AuditLogRepository {
  public abstract save(tx: Tx, entry: AuditLog): Promise<AuditLog>;

  /**
   * `offset` is an optional SQL SKIP for pagination (audit 2026-10-19:
   * the admin search validated `offset` but never passed it through).
   * Defaults to 0; existing callers are unaffected.
   */
  public abstract findByUserId(
    tx: Tx,
    userId: UserId,
    limit: number,
    range?: AuditLogTimeRange,
    offset?: number,
  ): Promise<ReadonlyArray<AuditLog>>;

  public abstract findByEventType(
    tx: Tx,
    eventType: AuditEventType,
    limit: number,
    range?: AuditLogTimeRange,
    offset?: number,
  ): Promise<ReadonlyArray<AuditLog>>;
}

export const AUDIT_LOG_REPOSITORY = Symbol('AuditLogRepository');
