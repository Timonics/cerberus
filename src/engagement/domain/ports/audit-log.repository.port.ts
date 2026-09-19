import { Tx } from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { AuditLog } from '../aggregates/audit-log';
import { AuditEventType } from '../value-objects/audit-event-type';

export abstract class AuditLogRepository {
  public abstract save(tx: Tx, entry: AuditLog): Promise<AuditLog>;

  public abstract findByUserId(
    tx: Tx,
    userId: UserId,
    limit: number,
  ): Promise<ReadonlyArray<AuditLog>>;

  public abstract findByEventType(
    tx: Tx,
    eventType: AuditEventType,
    limit: number,
  ): Promise<ReadonlyArray<AuditLog>>;
}

export const AUDIT_LOG_REPOSITORY = Symbol('AuditLogRepository');
