import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { PasswordHash } from '../../../shared/domain/value-objects/password-hash';
import { Credential } from '../../domain/aggregates/credential';
import { UserId } from '../../domain/value-objects/user-id';
import {
  CREDENTIAL_REPOSITORY,
  CredentialRepository,
} from '../../domain/ports/credential.repository.port';

/**
 * Narrow `Tx` (typed as `unknown` in the domain) to Prisma's
 * TransactionClient. The narrowing is safe because we always pass a real
 * Prisma client / tx from within the same Prisma service.
 */
type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `CredentialRepository`.
 *
 * Maps rows from the `credentials` table to/from `Credential` aggregate
 * instances. The mapping is intentionally explicit (no ORM magic) so we
 * can audit every field. Domain code never sees the Prisma row type.
 */
@Injectable()
export class PrismaCredentialRepository extends CredentialRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: UserId): Promise<Credential | null> {
    const client = tx as PrismaTx;
    const row = await client.credential.findUnique({
      where: { userId: id.value },
    });
    return row ? this.toDomain(row) : null;
  }

  public async save(tx: Tx, credential: Credential): Promise<Credential> {
    const client = tx as PrismaTx;
    const data = {
      userId: credential.userId.value,
      passwordHash: credential.passwordHash.value,
      passwordChangedAt: credential.passwordChangedAt,
      lockedUntil: credential.lockedUntil,
    };
    const row = await client.credential.upsert({
      where: { userId: credential.userId.value },
      create: data,
      update: data,
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: UserId): Promise<void> {
    const client = tx as PrismaTx;
    await client.credential.delete({ where: { userId: id.value } });
  }

  private toDomain(row: {
    userId: string;
    passwordHash: string;
    passwordChangedAt: Date;
    lockedUntil: Date | null;
    createdAt: Date;
    updatedAt: Date;
  }): Credential {
    return Credential.fromPersistence({
      userId: UserId.rehydrate(row.userId),
      passwordHash: PasswordHash.rehydrate(row.passwordHash),
      passwordChangedAt: row.passwordChangedAt,
      lockedUntil: row.lockedUntil,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

export const PRISMA_CREDENTIAL_REPOSITORY = CREDENTIAL_REPOSITORY;
