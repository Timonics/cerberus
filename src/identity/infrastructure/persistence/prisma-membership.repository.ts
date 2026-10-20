import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { Membership } from '../../domain/aggregates/membership';
import { OrgId } from '../../domain/value-objects/org-id';
import { Role } from '../../domain/value-objects/role';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `MembershipRepository`.
 */
@Injectable()
export class PrismaMembershipRepository extends MembershipRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: string): Promise<Membership | null> {
    const client = tx as PrismaTx;
    const row = await client.membership.findUnique({ where: { id } });
    return row ? this.toDomain(row) : null;
  }

  public async findByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<Membership | null> {
    const client = tx as PrismaTx;
    // 2026-10-19: users can now hold MULTIPLE memberships (personal org
    // + an org joined via verified email domain). V1 callers resolve
    // "the user's org" through this method, so it must deterministically
    // return the FIRST-CREATED membership — the personal-org one —
    // rather than an arbitrary row.
    const row = await client.membership.findFirst({
      where: { userId: userId.value },
      orderBy: { createdAt: 'asc' },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findByOrganizationId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<Membership>> {
    const client = tx as PrismaTx;
    const rows = await client.membership.findMany({
      where: { organizationId: organizationId.value },
    });
    return rows.map((r) => this.toDomain(r));
  }

  public async save(tx: Tx, membership: Membership): Promise<Membership> {
    const client = tx as PrismaTx;
    const data = {
      id: membership.id,
      userId: membership.userId.value,
      organizationId: membership.organizationId.value,
      role: membership.role.toString() as 'OWNER' | 'ADMIN' | 'MEMBER',
    };
    const row = await client.membership.upsert({
      where: { id: membership.id },
      create: data,
      update: { role: data.role },
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: string): Promise<void> {
    const client = tx as PrismaTx;
    await client.membership.delete({ where: { id } });
  }

  private toDomain(row: {
    id: string;
    userId: string;
    organizationId: string;
    role: string;
    createdAt: Date;
    updatedAt: Date;
  }): Membership {
    return Membership.fromPersistence({
      id: row.id,
      userId: UserId.rehydrate(row.userId),
      organizationId: OrgId.rehydrate(row.organizationId),
      role: Role.rehydrate(row.role),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

export const PRISMA_MEMBERSHIP_REPOSITORY = MEMBERSHIP_REPOSITORY;
