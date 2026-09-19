import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { AuditLog } from '../../domain/aggregates/audit-log';
import { AuditEventType } from '../../domain/value-objects/audit-event-type';
import {
  AUDIT_LOG_REPOSITORY,
  AuditLogRepository,
} from '../../domain/ports/audit-log.repository.port';

export interface RecordAuditEventInput {
  userId: string | null;
  eventType: string;
  payload: Readonly<Record<string, unknown>>;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Append a single audit-log row.
 *
 * Pure write — does NOT publish a domain event (the audit log is a
 * consumer of events, not a producer).
 */
@Injectable()
export class RecordAuditEventUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly repo: AuditLogRepository,
  ) {}

  public async execute(input: RecordAuditEventInput): Promise<AuditLog> {
    const entry = AuditLog.create({
      id: this.idGenerator.generate(),
      userId: input.userId,
      eventType: AuditEventType.create(input.eventType),
      payload: input.payload,
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
      clock: this.clock,
    });
    return this.txRunner.run<AuditLog>((tx: Tx) => this.repo.save(tx, entry));
  }
}
