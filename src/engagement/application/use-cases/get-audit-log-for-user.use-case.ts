import { Inject, Injectable } from '@nestjs/common';
import {
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { AuditLog } from '../../domain/aggregates/audit-log';
import {
  AUDIT_LOG_REPOSITORY,
  AuditLogRepository,
} from '../../domain/ports/audit-log.repository.port';

export interface GetAuditLogForUserInput {
  userId: string;
  limit: number;
}

export interface AuditLogEntry {
  id: string;
  eventType: string;
  /** V1.5: this was missing — added so GraphQL resolvers can show who the event is attributed to. */
  userId: string | null;
  payload: Readonly<Record<string, unknown>>;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

export interface GetAuditLogForUserResult {
  entries: ReadonlyArray<AuditLogEntry>;
}

/**
 * Read the audit log for a single user (most recent first).
 *
 * V1: any authenticated user can read their OWN log. Admin access for
 * any user lands in the Administration context (Phase 15).
 */
@Injectable()
export class GetAuditLogForUserUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(AUDIT_LOG_REPOSITORY) private readonly repo: AuditLogRepository,
  ) {}

  public async execute(
    input: GetAuditLogForUserInput,
  ): Promise<GetAuditLogForUserResult> {
    const userId = UserId.create(input.userId);
    const limit = Math.min(Math.max(input.limit, 1), 500);
    return this.txRunner.run<GetAuditLogForUserResult>(async (tx: Tx) => {
      const rows = await this.repo.findByUserId(tx, userId, limit);
      return {
        entries: rows.map((row: AuditLog) => ({
          id: row.id,
          eventType: row.eventType.value,
          userId: row.userId,
          payload: row.payload,
          ipAddress: row.ipAddress,
          userAgent: row.userAgent,
          createdAt: row.createdAt,
        })),
      };
    });
  }
}
