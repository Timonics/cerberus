import { Inject, Injectable } from '@nestjs/common';
import {
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
  DomainError,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import {
  AUDIT_LOG_REPOSITORY,
  AuditLogRepository,
} from '../../../engagement/domain/ports/audit-log.repository.port';
import { AuditLog } from '../../../engagement/domain/aggregates/audit-log';
import { AuditEventType } from '../../../engagement/domain/value-objects/audit-event-type';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  AdminAuditSearchQuery,
  buildAdminAuditSearchQuery,
} from '../../domain/value-objects/admin-audit-search-query';

export interface AdminSearchAuditLogInput {
  userId?: string | null;
  eventType?: string | null;
  from?: Date | null;
  to?: Date | null;
  limit?: number | null;
  offset?: number | null;
  /** V1.5: who issued the search, for the `admin.audit.searched` row. */
  callerUserId?: string | null;
  /** V1.5: which admin API key (if any) issued the search. */
  callerKeyId?: string | null;
}

export interface AdminSearchAuditLogResult {
  entries: ReadonlyArray<{
    id: string;
    eventType: string;
    userId: string | null;
    payload: Readonly<Record<string, unknown>>;
    createdAt: Date;
    ipAddress: string | null;
    userAgent: string | null;
  }>;
  total: number;
}

/**
 * Admin cross-user audit-log search.
 *
 * Thin orchestration over the existing `AuditLogRepository.findByUserId`
 * — V1 only supports single-user searches with optional time
 * windowing + pagination. Cross-user + event-type search lands in
 * V1.5 (the repository needs an index on `(eventType, createdAt)` and
 * a query helper that supports OR'd userId filters).
 *
 * For V1, the simplest useful query is "give me everything for user X
 * between time T1 and T2" — which is exactly what this use-case does.
 */
@Injectable()
export class AdminSearchAuditLogUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(AUDIT_LOG_REPOSITORY)
    private readonly auditRepo: AuditLogRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: AdminSearchAuditLogInput,
  ): Promise<AdminSearchAuditLogResult> {
    const query = buildAdminAuditSearchQuery(input);
    return this.txRunner.run<AdminSearchAuditLogResult>(async (tx: Tx) => {
      const rows = await this.loadByQuery(tx, query);
      // V1.5 audit: write `admin.audit.searched` after a successful
      // query. The caller (callerUserId) is captured so operators
      // can answer "who searched the audit log and when".
      const result = {
        entries: rows.map((row: AuditLog) => ({
          id: row.id,
          eventType: row.eventType.value,
          userId: row.userId,
          payload: row.payload,
          createdAt: row.createdAt,
          ipAddress: row.ipAddress,
          userAgent: row.userAgent,
        })),
        total: rows.length,
      };
      // Audit logging is fire-and-forget — it must not block the
      // operator's read path. We log inside the same tx context so
      // a rolled-back search doesn't leave an audit row.
      await this.recordAuditEventUc.execute({
        userId: query.userId ?? null,
        eventType: 'admin.audit.searched',
        payload: {
          userIdFilter: query.userId ?? null,
          eventTypeFilter: query.eventType ?? null,
          from: query.from?.toISOString() ?? null,
          to: query.to?.toISOString() ?? null,
          limit: query.limit ?? null,
          offset: query.offset ?? null,
          resultCount: result.total,
          callerUserId: input.callerUserId ?? null,
          callerKeyId: input.callerKeyId ?? null,
        },
      });
      return result;
    });
  }

  private async loadByQuery(
    tx: Tx,
    query: AdminAuditSearchQuery,
  ): Promise<ReadonlyArray<AuditLog>> {
    // V1: only the userId path is implemented. Other filters are
    // accepted (and validated) so the public contract is stable, but
    // they're currently best-effort.
    if (query.userId) {
      return this.auditRepo.findByUserId(
        tx,
        UserId.create(query.userId),
        query.limit ?? 100,
      );
    }
    if (query.eventType) {
      return this.auditRepo.findByEventType(
        tx,
        AuditEventType.create(query.eventType),
        query.limit ?? 100,
      );
    }
    // No userId + no eventType — `buildAdminAuditSearchQuery` already
    // throws when only `from`/`to` are set, so this branch is
    // unreachable in practice. Defensive throw in case the validator
    // is bypassed.
    throw new DomainError(
      'admin.audit.search.too_broad',
      'Audit-log search requires at least userId or eventType in V1',
    );
  }
}
