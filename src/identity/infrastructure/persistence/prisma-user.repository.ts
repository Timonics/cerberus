import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { Email } from '../../../shared/domain/value-objects/email';
import { User } from '../../domain/aggregates/user';
import { OrgId } from '../../domain/value-objects/org-id';
import { UserId } from '../../domain/value-objects/user-id';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `UserRepository`.
 *
 * Maps rows from the `users` table to/from `User` aggregate instances.
 *
 * Uniqueness:
 *   The `email` column has a UNIQUE constraint. When two registrations
 *   race, Prisma raises `P2002` on the loser; the use-case catches it
 *   and raises `DomainError('identity.email.taken', ...)` so the HTTP
 *   layer can map it to 409.
 */
@Injectable()
export class PrismaUserRepository extends UserRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: UserId): Promise<User | null> {
    const client = tx as PrismaTx;
    const row = await client.user.findUnique({ where: { id: id.value } });
    return row ? this.toDomain(row) : null;
  }

  public async findByEmail(tx: Tx, email: string): Promise<User | null> {
    const client = tx as PrismaTx;
    const normalized = Email.create(email).value;
    const row = await client.user.findUnique({ where: { email: normalized } });
    return row ? this.toDomain(row) : null;
  }

  public async existsWithEmail(tx: Tx, email: string): Promise<boolean> {
    const client = tx as PrismaTx;
    const normalized = Email.create(email).value;
    const count = await client.user.count({ where: { email: normalized } });
    return count > 0;
  }

  public async save(tx: Tx, user: User): Promise<User> {
    const client = tx as PrismaTx;
    const data = {
      id: user.id.value,
      organizationId: user.organizationId.value,
      email: user.email.value,
      displayName: user.displayName,
      emailVerifiedAt: user.emailVerifiedAt,
      deletedAt: user.deletedAt,
    };
    const row = await client.user.upsert({
      where: { id: user.id.value },
      create: data,
      update: {
        organizationId: data.organizationId,
        email: data.email,
        displayName: data.displayName,
        emailVerifiedAt: data.emailVerifiedAt,
        deletedAt: data.deletedAt,
      },
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: UserId): Promise<void> {
    const client = tx as PrismaTx;
    await client.user.delete({ where: { id: id.value } });
  }

  private toDomain(row: {
    id: string;
    organizationId: string;
    email: string;
    displayName: string | null;
    emailVerifiedAt: Date | null;
    deletedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
  }): User {
    return User.fromPersistence({
      id: UserId.rehydrate(row.id),
      organizationId: OrgId.rehydrate(row.organizationId),
      email: Email.rehydrate(row.email),
      displayName: row.displayName,
      emailVerifiedAt: row.emailVerifiedAt,
      deletedAt: row.deletedAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

export const PRISMA_USER_REPOSITORY = USER_REPOSITORY;
