import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { EmailVerification } from '../../domain/aggregates/email-verification';
import {
  EMAIL_VERIFICATION_REPOSITORY,
  EmailVerificationRepository,
} from '../../domain/ports/email-verification.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaEmailVerificationRepository extends EmailVerificationRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findByTokenHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<EmailVerification | null> {
    const client = tx as PrismaTx;
    const row = await client.emailVerification.findUnique({
      where: { tokenHash },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<EmailVerification | null> {
    const client = tx as PrismaTx;
    const row = await client.emailVerification.findFirst({
      where: {
        userId: userId.value,
        consumedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
    return row ? this.toDomain(row) : null;
  }

  public async save(
    tx: Tx,
    verification: EmailVerification,
  ): Promise<EmailVerification> {
    const client = tx as PrismaTx;
    const data = {
      id: verification.id,
      userId: verification.userId.value,
      tokenHash: verification.tokenHash,
      expiresAt: verification.expiresAt,
      consumedAt: verification.consumedAt,
      createdAt: verification.createdAt,
    };
    const row = await client.emailVerification.upsert({
      where: { id: verification.id },
      create: data,
      update: {
        consumedAt: data.consumedAt,
      },
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: string): Promise<void> {
    const client = tx as PrismaTx;
    await client.emailVerification.delete({ where: { id } });
  }

  private toDomain(row: {
    id: string;
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    consumedAt: Date | null;
    createdAt: Date;
  }): EmailVerification {
    return EmailVerification.fromPersistence({
      id: row.id,
      userId: UserId.rehydrate(row.userId),
      tokenHash: row.tokenHash,
      expiresAt: row.expiresAt,
      consumedAt: row.consumedAt,
      createdAt: row.createdAt,
    });
  }
}

void EMAIL_VERIFICATION_REPOSITORY;
