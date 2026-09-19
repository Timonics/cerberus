import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { AdminApiKey } from '../../domain/aggregates/admin-api-key';
import {
  ADMIN_API_KEY_REPOSITORY,
  AdminApiKeyRepository,
} from '../../domain/ports/admin-api-key.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaAdminApiKeyRepository extends AdminApiKeyRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: string): Promise<AdminApiKey | null> {
    const client = tx as PrismaTx;
    const row = await client.adminApiKey.findUnique({ where: { id } });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByPlaintextHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<AdminApiKey | null> {
    const client = tx as PrismaTx;
    const now = new Date();
    const row = await client.adminApiKey.findFirst({
      where: {
        keyHash: tokenHash,
        revokedAt: null,
        expiresAt: { gt: now },
      },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByPlaintextHashIgnoringExpiry(
    tx: Tx,
    tokenHash: string,
  ): Promise<AdminApiKey | null> {
    // Used by the guard to differentiate "valid but expired" from
    // "unknown" so the audit log can record the right reason.
    const client = tx as PrismaTx;
    const row = await client.adminApiKey.findFirst({
      where: { keyHash: tokenHash },
    });
    return row ? this.toDomain(row) : null;
  }

  public async save(tx: Tx, key: AdminApiKey): Promise<AdminApiKey> {
    const client = tx as PrismaTx;
    const data = {
      id: key.id,
      name: key.name,
      keyHash: key.keyHash,
      role: key.role.value,
      createdAt: key.createdAt,
      createdBy: key.createdBy,
      lastUsedAt: key.lastUsedAt,
      expiresAt: key.expiresAt,
      revokedAt: key.revokedAt,
      notes: key.notes,
    };
    const row = await client.adminApiKey.upsert({
      where: { id: key.id },
      create: data,
      update: {
        lastUsedAt: data.lastUsedAt,
        revokedAt: data.revokedAt,
      },
    });
    return this.toDomain(row);
  }

  public async listAll(tx: Tx): Promise<ReadonlyArray<AdminApiKey>> {
    const client = tx as PrismaTx;
    const rows = await client.adminApiKey.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.toDomain(r));
  }

  public async markUsed(tx: Tx, id: string, when: Date): Promise<AdminApiKey> {
    const client = tx as PrismaTx;
    const row = await client.adminApiKey.update({
      where: { id },
      data: { lastUsedAt: when },
    });
    return this.toDomain(row);
  }

  private toDomain(row: {
    id: string;
    name: string;
    keyHash: string;
    role: string;
    createdAt: Date;
    createdBy: string;
    lastUsedAt: Date | null;
    expiresAt: Date;
    revokedAt: Date | null;
    notes: string | null;
  }): AdminApiKey {
    return AdminApiKey.fromPersistence({
      id: row.id,
      name: row.name,
      keyHash: row.keyHash,
      role: row.role,
      createdAt: row.createdAt,
      createdBy: row.createdBy,
      lastUsedAt: row.lastUsedAt,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt,
      notes: row.notes,
    });
  }
}

void ADMIN_API_KEY_REPOSITORY;
