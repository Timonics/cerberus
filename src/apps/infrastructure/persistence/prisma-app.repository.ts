import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Clock, Tx } from '../../../shared/domain';
import { App } from '../../domain/aggregates/app';
import { AppApiKey } from '../../domain/aggregates/app-api-key';
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaAppRepository extends AppRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: string): Promise<App | null> {
    const client = tx as PrismaTx;
    const row = await client.app.findUnique({
      where: { id },
      include: { apiKeys: { orderBy: { createdAt: 'desc' }, take: 1 } },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByKeyHash(
    tx: Tx,
    keyHash: string,
  ): Promise<App | null> {
    const client = tx as PrismaTx;
    const now = new Date();
    // Find an active key row + its parent app.
    const row = await client.appApiKey.findFirst({
      where: {
        keyHash,
        revokedAt: null,
        expiresAt: { gt: now },
        app: { revokedAt: null },
      },
      include: { app: { include: { apiKeys: true } } },
    });
    if (!row) return null;
    return this.toDomainFromKey(row);
  }

  public async save(tx: Tx, app: App): Promise<App> {
    const client = tx as PrismaTx;
    // Upsert the app row.
    await client.app.upsert({
      where: { id: app.id },
      create: {
        id: app.id,
        name: app.name,
        description: app.description,
        defaultOrgSlug: app.defaultOrgSlug,
        createdAt: app.createdAt,
        contactEmail: app.contactEmail,
        revokedAt: app.revokedAt,
        notes: app.notes,
      },
      update: {
        name: app.name,
        description: app.description,
        defaultOrgSlug: app.defaultOrgSlug,
        revokedAt: app.revokedAt,
        notes: app.notes,
      },
    });
    // Upsert the current key row, if any.
    if (app.currentKey) {
      const k = app.currentKey;
      await client.appApiKey.upsert({
        where: { id: k.id },
        create: {
          id: k.id,
          appId: k.appId,
          keyHash: k.keyHash,
          name: k.name,
          createdAt: k.createdAt,
          lastUsedAt: k.lastUsedAt,
          expiresAt: k.expiresAt,
          revokedAt: k.revokedAt,
        },
        update: {
          lastUsedAt: k.lastUsedAt,
          revokedAt: k.revokedAt,
        },
      });
    }
    // Re-fetch with the include for a complete aggregate.
    return this.findById(tx, app.id) as Promise<App>;
  }

  private toDomain(row: {
    id: string;
    name: string;
    description: string | null;
    defaultOrgSlug: string | null;
    createdAt: Date;
    contactEmail: string;
    revokedAt: Date | null;
    notes: string | null;
    apiKeys?: Array<{
      id: string;
      appId: string;
      keyHash: string;
      name: string;
      createdAt: Date;
      lastUsedAt: Date | null;
      expiresAt: Date;
      revokedAt: Date | null;
    }>;
  }): App {
    const liveKey = row.apiKeys?.find(
      (k) => k.revokedAt === null && k.expiresAt.getTime() > Date.now(),
    );
    return App.rehydrate({
      id: row.id,
      name: row.name,
      description: row.description,
      defaultOrgSlug: row.defaultOrgSlug,
      createdAt: row.createdAt,
      contactEmail: row.contactEmail,
      revokedAt: row.revokedAt,
      notes: row.notes,
      currentKey: liveKey ? this.toKeyDomain(liveKey) : null,
    });
  }

  private toDomainFromKey(row: {
    app: {
      id: string;
      name: string;
      description: string | null;
      defaultOrgSlug: string | null;
      createdAt: Date;
      contactEmail: string;
      revokedAt: Date | null;
      notes: string | null;
      apiKeys: Array<{
        id: string;
        appId: string;
        keyHash: string;
        name: string;
        createdAt: Date;
        lastUsedAt: Date | null;
        expiresAt: Date;
        revokedAt: Date | null;
      }>;
    };
  }): App {
    const liveKey = row.app.apiKeys.find(
      (k) => k.revokedAt === null && k.expiresAt.getTime() > Date.now(),
    );
    return App.rehydrate({
      id: row.app.id,
      name: row.app.name,
      description: row.app.description,
      defaultOrgSlug: row.app.defaultOrgSlug,
      createdAt: row.app.createdAt,
      contactEmail: row.app.contactEmail,
      revokedAt: row.app.revokedAt,
      notes: row.app.notes,
      currentKey: liveKey ? this.toKeyDomain(liveKey) : null,
    });
  }

  private toKeyDomain(row: {
    id: string;
    appId: string;
    keyHash: string;
    name: string;
    createdAt: Date;
    lastUsedAt: Date | null;
    expiresAt: Date;
    revokedAt: Date | null;
  }): AppApiKey {
    return AppApiKey.fromPersistence({
      id: row.id,
      appId: row.appId,
      keyHash: row.keyHash,
      name: row.name,
      createdAt: row.createdAt,
      lastUsedAt: row.lastUsedAt,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt,
    });
  }

  public async revokeKey(tx: Tx, keyId: string, clock: Clock): Promise<void> {
    const client = tx as PrismaTx;
    await client.appApiKey.update({
      where: { id: keyId },
      data: { revokedAt: clock.now() },
    });
  }
}

void APP_REPOSITORY;
