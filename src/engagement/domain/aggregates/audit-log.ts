import { Clock, DomainError } from '../../../shared/domain';
import { AuditEventType } from '../value-objects/audit-event-type';

/**
 * Append-only audit log entry.
 *
 * Once created, an AuditLog row is NEVER updated or deleted. This is
 * by design — the audit log is the system of record for "what
 * happened when" and must be tamper-evident.
 *
 * `payload` is a free-form JSON object whose shape depends on the
 * `eventType`. We don't validate the shape here — the producer (the
 * use-case) is responsible for sending the right payload.
 */
export class AuditLog {
  private constructor(
    public readonly id: string,
    public readonly userId: string | null,
    public readonly eventType: AuditEventType,
    public readonly payload: Readonly<Record<string, unknown>>,
    public readonly ipAddress: string | null,
    public readonly userAgent: string | null,
    public readonly createdAt: Date,
  ) {}

  public static create(params: {
    id: string;
    userId: string | null;
    eventType: AuditEventType;
    payload: Readonly<Record<string, unknown>>;
    ipAddress: string | null;
    userAgent: string | null;
    clock: Clock;
  }): AuditLog {
    if (!params.userId && params.eventType.value.startsWith('identity.')) {
      // Identity events must always have a user. Other events (e.g.
      // `engagement.password_reset.requested`) may legitimately have a
      // null user when the request hasn't been authenticated yet.
      throw new DomainError(
        'domain.invariant_violation',
        'Identity audit events must reference a userId',
      );
    }
    return new AuditLog(
      params.id,
      params.userId,
      params.eventType,
      params.payload,
      params.ipAddress,
      params.userAgent,
      params.clock.now(),
    );
  }

  public static fromPersistence(params: {
    id: string;
    userId: string | null;
    eventType: AuditEventType;
    payload: Readonly<Record<string, unknown>>;
    ipAddress: string | null;
    userAgent: string | null;
    createdAt: Date;
  }): AuditLog {
    return new AuditLog(
      params.id,
      params.userId,
      params.eventType,
      params.payload,
      params.ipAddress,
      params.userAgent,
      params.createdAt,
    );
  }
}
