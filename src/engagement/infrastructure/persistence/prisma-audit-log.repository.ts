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
  ): Promise<ReadonlyArray<AuditLog>> {
    const client = tx as PrismaTx;
    const rows = await client.auditLog.findMany({
      where: { userId: userId.value },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return rows.map((row) =>
      AuditLog.fromPersistence({
        id: row.id,
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
  ): Promise<ReadonlyArray<AuditLog>> {
    const client = tx as PrismaTx;
    const rows = await client.auditLog.findMany({
      where: { eventType: eventType.value },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return rows.map((row) =>
      AuditLog.fromPersistence({
        id: row.id,
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

void AUDIT_LOG_REPOSITORY;
