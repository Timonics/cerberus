import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { PasswordReset } from '../../domain/aggregates/password-reset';
import {
  PASSWORD_RESET_REPOSITORY,
  PasswordResetRepository,
} from '../../domain/ports/password-reset.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaPasswordResetRepository extends PasswordResetRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findByTokenHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<PasswordReset | null> {
    const client = tx as PrismaTx;
    const row = await client.passwordReset.findUnique({
      where: { tokenHash },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<PasswordReset | null> {
    const client = tx as PrismaTx;
    const row = await client.passwordReset.findFirst({
      where: {
        userId: userId.value,
        consumedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
    return row ? this.toDomain(row) : null;
  }

  public async save(tx: Tx, reset: PasswordReset): Promise<PasswordReset> {
    const client = tx as PrismaTx;
    const data = {
      id: reset.id,
      userId: reset.userId.value,
      tokenHash: reset.tokenHash,
      expiresAt: reset.expiresAt,
      consumedAt: reset.consumedAt,
      createdAt: reset.createdAt,
    };
    const row = await client.passwordReset.upsert({
      where: { id: reset.id },
      create: data,
      update: { consumedAt: data.consumedAt },
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: string): Promise<void> {
    const client = tx as PrismaTx;
    await client.passwordReset.delete({ where: { id } });
  }

  private toDomain(row: {
    id: string;
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    consumedAt: Date | null;
    createdAt: Date;
  }): PasswordReset {
    return PasswordReset.fromPersistence({
      id: row.id,
      userId: UserId.rehydrate(row.userId),
      tokenHash: row.tokenHash,
      expiresAt: row.expiresAt,
      consumedAt: row.consumedAt,
      createdAt: row.createdAt,
    });
  }
}

void PASSWORD_RESET_REPOSITORY;
