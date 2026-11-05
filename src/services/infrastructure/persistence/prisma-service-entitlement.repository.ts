import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import { ServiceEntitlement } from '../../domain/aggregates/service-entitlement';
import { Service } from '../../domain/aggregates/service';
import {
  EntitlementWithService,
  SERVICE_ENTITLEMENT_REPOSITORY,
  ServiceEntitlementRepository,
} from '../../domain/ports/service-entitlement.repository.port';
import { ServiceSlug } from '../../domain/value-objects/service-slug';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

type EntitlementRow = {
  id: string;
  organizationId: string;
  serviceId: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
};

@Injectable()
export class PrismaServiceEntitlementRepository extends ServiceEntitlementRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findByOrgAndService(
    tx: Tx,
    organizationId: OrgId,
    serviceId: string,
  ): Promise<ServiceEntitlement | null> {
    const client = tx as PrismaTx;
    const row = await client.serviceEntitlement.findUnique({
      where: {
        organizationId_serviceId: {
          organizationId: organizationId.value,
          serviceId,
        },
      },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveWithServiceByOrgId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<EntitlementWithService>> {
    const client = tx as PrismaTx;
    const rows = await client.serviceEntitlement.findMany({
      where: {
        organizationId: organizationId.value,
        status: 'ACTIVE',
        service: { status: 'ACTIVE' },
      },
      include: { service: true },
    });
    return rows.map((row) => this.toDomainWithService(row));
  }

  public async findWithServiceByOrgId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<EntitlementWithService>> {
    const client = tx as PrismaTx;
    const rows = await client.serviceEntitlement.findMany({
      where: { organizationId: organizationId.value },
      include: { service: true },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map((row) => this.toDomainWithService(row));
  }

  public async save(
    tx: Tx,
    entitlement: ServiceEntitlement,
  ): Promise<ServiceEntitlement> {
    const client = tx as PrismaTx;
    const data = {
      id: entitlement.id,
      organizationId: entitlement.organizationId.value,
      serviceId: entitlement.serviceId,
      status: entitlement.status,
      createdAt: entitlement.createdAt,
      updatedAt: entitlement.updatedAt,
    };
    const row = await client.serviceEntitlement.upsert({
      where: { id: entitlement.id },
      create: data,
      update: { status: data.status, updatedAt: data.updatedAt },
    });
    return this.toDomain(row);
  }

  private toDomain(row: EntitlementRow): ServiceEntitlement {
    return ServiceEntitlement.fromPersistence({
      id: row.id,
      organizationId: OrgId.rehydrate(row.organizationId),
      serviceId: row.serviceId,
      status: row.status as 'ACTIVE' | 'SUSPENDED' | 'REVOKED',
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }

  private toDomainWithService(
    row: EntitlementRow & {
      service: {
        id: string;
        slug: string;
        name: string;
        description: string | null;
        status: string;
        createdAt: Date;
        updatedAt: Date;
      };
    },
  ): EntitlementWithService {
    return {
      entitlement: this.toDomain(row),
      service: Service.fromPersistence({
        id: row.service.id,
        slug: ServiceSlug.rehydrate(row.service.slug),
        name: row.service.name,
        description: row.service.description,
        status: row.service.status as 'ACTIVE' | 'INACTIVE',
        createdAt: row.service.createdAt,
        updatedAt: row.service.updatedAt,
      }),
    };
  }
}

void SERVICE_ENTITLEMENT_REPOSITORY;
