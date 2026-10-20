import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { AuditLog } from '../../domain/aggregates/audit-log';
import { AuditEventType } from '../../domain/value-objects/audit-event-type';
import {
  AUDIT_LOG_REPOSITORY,
  AuditLogRepository,
  AuditLogTimeRange,
} from '../../domain/ports/audit-log.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaAuditLogRepository extends AuditLogRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async save(tx: Tx, entry: AuditLog): Promise<AuditLog> {
    const client = tx as PrismaTx;
    const row = await client.auditLog.create({
      data: {
        id: entry.id,
        eventId: entry.eventId,
        userId: entry.userId,
        eventType: entry.eventType.value,
        payload: entry.payload as unknown as Prisma.InputJsonValue,
        ipAddress: entry.ipAddress,
        userAgent: entry.userAgent,
        createdAt: entry.createdAt,
      },
    });
    return AuditLog.fromPersistence({
      id: row.id,
      eventId: row.eventId,
      userId: row.userId,
      eventType: AuditEventType.rehydrate(row.eventType),
      payload: row.payload as Readonly<Record<string, unknown>>,
      ipAddress: row.ipAddress,
      userAgent: row.userAgent,
      createdAt: row.createdAt,
    });
  }

  public async findByUserId(
    tx: Tx,
    userId: UserId,
    limit: number,
    range?: AuditLogTimeRange,
    offset = 0,
  ): Promise<ReadonlyArray<AuditLog>> {
    const client = tx as PrismaTx;
    const rows = await client.auditLog.findMany({
      where: {
        userId: userId.value,
        ...buildTimeRange(range),
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
    return rows.map((row) =>
      AuditLog.fromPersistence({
        id: row.id,
        eventId: row.eventId,
        userId: row.userId,
        eventType: AuditEventType.rehydrate(row.eventType),
        payload: row.payload as object as Readonly<Record<string, unknown>>,
        ipAddress: row.ipAddress,
        userAgent: row.userAgent,
        createdAt: row.createdAt,
      }),
    );
  }

  public async findByEventType(
    tx: Tx,
    eventType: AuditEventType,
    limit: number,
    range?: AuditLogTimeRange,
    offset = 0,
  ): Promise<ReadonlyArray<AuditLog>> {
    const client = tx as PrismaTx;
    const rows = await client.auditLog.findMany({
      where: {
        eventType: eventType.value,
        ...buildTimeRange(range),
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
    return rows.map((row) =>
      AuditLog.fromPersistence({
        id: row.id,
        eventId: row.eventId,
        userId: row.userId,
        eventType: AuditEventType.rehydrate(row.eventType),
        payload: row.payload as object as Readonly<Record<string, unknown>>,
        ipAddress: row.ipAddress,
        userAgent: row.userAgent,
        createdAt: row.createdAt,
      }),
    );
  }
}

/**
 * Build the `createdAt` clause for a time-range filter.
 * Returns `undefined` when no range is supplied so Prisma treats
 * it as "no constraint". V1.5: this is the actual SQL filter —
 * previously the use-case validated these inputs but the
 * repository ignored them, so every search ran unfiltered.
 */
function buildTimeRange(range: AuditLogTimeRange | undefined): {
  createdAt?: { gte?: Date; lte?: Date };
} {
  if (!range) return {};
  const clause: { gte?: Date; lte?: Date } = {};
  if (range.from !== undefined && range.from !== null) {
    clause.gte = range.from;
  }
  if (range.to !== undefined && range.to !== null) {
    clause.lte = range.to;
  }
  return Object.keys(clause).length === 0 ? {} : { createdAt: clause };
}

void AUDIT_LOG_REPOSITORY;
