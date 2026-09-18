import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { Organization } from '../../domain/aggregates/organization';
import { OrgId } from '../../domain/value-objects/org-id';
import { OrgSlug } from '../../domain/value-objects/org-slug';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../domain/ports/organization.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `OrganizationRepository`.
 */
@Injectable()
export class PrismaOrganizationRepository extends OrganizationRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: OrgId): Promise<Organization | null> {
    const client = tx as PrismaTx;
    const row = await client.organization.findUnique({
      where: { id: id.value },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findBySlug(tx: Tx, slug: OrgSlug): Promise<Organization | null> {
    const client = tx as PrismaTx;
    const row = await client.organization.findUnique({
      where: { slug: slug.value },
    });
    return row ? this.toDomain(row) : null;
  }

  public async existsWithSlug(tx: Tx, slug: OrgSlug): Promise<boolean> {
    const client = tx as PrismaTx;
    const count = await client.organization.count({
      where: { slug: slug.value },
    });
    return count > 0;
  }

  public async save(tx: Tx, org: Organization): Promise<Organization> {
    const client = tx as PrismaTx;
    const data = {
      id: org.id.value,
      slug: org.slug.value,
      name: org.name,
    };
    const row = await client.organization.upsert({
      where: { id: org.id.value },
      create: data,
      update: { slug: data.slug, name: data.name },
    });
    return this.toDomain(row);
  }

  public async delete(tx: Tx, id: OrgId): Promise<void> {
    const client = tx as PrismaTx;
    await client.organization.delete({ where: { id: id.value } });
  }

  private toDomain(row: {
    id: string;
    slug: string;
    name: string;
    createdAt: Date;
    updatedAt: Date;
  }): Organization {
    return Organization.fromPersistence({
      id: OrgId.rehydrate(row.id),
      slug: OrgSlug.rehydrate(row.slug),
      name: row.name,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

export const PRISMA_ORGANIZATION_REPOSITORY = ORGANIZATION_REPOSITORY;
