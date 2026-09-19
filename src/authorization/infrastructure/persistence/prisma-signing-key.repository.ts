import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { SigningKey } from '../../domain/aggregates/signing-key';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `SigningKeyRepository`.
 *
 * Notable: `rotate` is an atomic UPDATE on two rows (retire the old,
 * promote the new). We use a transaction to ensure the database never
 * has zero current keys.
 */
@Injectable()
export class PrismaSigningKeyRepository extends SigningKeyRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async getCurrent(tx: Tx): Promise<SigningKey> {
    const client = tx as PrismaTx;
    const row = await client.signingKey.findFirst({
      where: { isCurrent: true },
      orderBy: { createdAt: 'desc' },
    });
    if (!row) {
      throw new Error('No current signing key — run rotate first');
    }
    return this.toDomain(row);
  }

  public async findByKid(tx: Tx, kid: string): Promise<SigningKey | null> {
    const client = tx as PrismaTx;
    const row = await client.signingKey.findUnique({ where: { kid } });
    return row ? this.toDomain(row) : null;
  }

  public async findVerifyingAt(
    tx: Tx,
    when: Date,
  ): Promise<ReadonlyArray<SigningKey>> {
    const client = tx as PrismaTx;
    const rows = await client.signingKey.findMany({
      where: {
        OR: [{ expiresAt: null }, { expiresAt: { gt: when } }],
      },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => this.toDomain(r));
  }

  public async save(tx: Tx, key: SigningKey): Promise<SigningKey> {
    const client = tx as PrismaTx;
    const data = {
      id: key.id,
      kid: key.kid,
      algorithm: key.algorithm,
      privatePem: key.privatePem,
      publicPem: key.publicPem,
      createdAt: key.createdAt,
      retiredAt: key.retiredAt,
      expiresAt: key.expiresAt,
      isCurrent: key.isCurrent,
    };
    const row = await client.signingKey.upsert({
      where: { kid: key.kid },
      create: data,
      update: {
        retiredAt: data.retiredAt,
        expiresAt: data.expiresAt,
        isCurrent: data.isCurrent,
      },
    });
    return this.toDomain(row);
  }

  public async rotate(
    tx: Tx,
    retiredKeyId: string,
    newCurrentKey: SigningKey,
  ): Promise<SigningKey> {
    const client = tx as PrismaTx;
    // Retire the old one in the same transaction.
    await client.signingKey.update({
      where: { id: retiredKeyId },
      data: {
        isCurrent: false,
        retiredAt: newCurrentKey.createdAt, // approximate; set below if needed
        // expiresAt is set later by the use-case via the retire() method
      },
    });
    // Insert / update the new one as current.
    return this.save(tx, newCurrentKey);
  }

  private toDomain(row: {
    id: string;
    kid: string;
    algorithm: string;
    privatePem: string;
    publicPem: string;
    createdAt: Date;
    retiredAt: Date | null;
    expiresAt: Date | null;
    isCurrent: boolean;
  }): SigningKey {
    return SigningKey.fromPersistence({
      id: row.id,
      kid: row.kid,
      algorithm: row.algorithm,
      privatePem: row.privatePem,
      publicPem: row.publicPem,
      createdAt: row.createdAt,
      retiredAt: row.retiredAt,
      expiresAt: row.expiresAt,
      isCurrent: row.isCurrent,
    });
  }
}

// Suppress unused — symbol is referenced via the class binding.
void SIGNING_KEY_REPOSITORY;
