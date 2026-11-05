import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { Service } from '../../domain/aggregates/service';
import {
  SERVICE_REPOSITORY,
  ServiceRepository,
} from '../../domain/ports/service.repository.port';
import { ServiceSlug } from '../../domain/value-objects/service-slug';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

@Injectable()
export class PrismaServiceRepository extends ServiceRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findBySlug(tx: Tx, slug: ServiceSlug): Promise<Service | null> {
    const client = tx as PrismaTx;
    const row = await client.service.findUnique({
      where: { slug: slug.value },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findById(tx: Tx, id: string): Promise<Service | null> {
    const client = tx as PrismaTx;
    const row = await client.service.findUnique({ where: { id } });
    return row ? this.toDomain(row) : null;
  }

  public async save(tx: Tx, service: Service): Promise<Service> {
    const client = tx as PrismaTx;
    const data = {
      id: service.id,
      slug: service.slug.value,
      name: service.name,
      description: service.description,
      status: service.status,
      createdAt: service.createdAt,
      updatedAt: service.updatedAt,
    };
    const row = await client.service.upsert({
      where: { id: service.id },
      create: data,
      update: {
        name: data.name,
        description: data.description,
        status: data.status,
        updatedAt: data.updatedAt,
      },
    });
    return this.toDomain(row);
  }

  public async list(tx: Tx): Promise<ReadonlyArray<Service>> {
    const client = tx as PrismaTx;
    const rows = await client.service.findMany({
      orderBy: { createdAt: 'asc' },
    });
    return rows.map((row) => this.toDomain(row));
  }

  private toDomain(row: {
    id: string;
    slug: string;
    name: string;
    description: string | null;
    status: string;
    createdAt: Date;
    updatedAt: Date;
  }): Service {
    return Service.fromPersistence({
      id: row.id,
      slug: ServiceSlug.rehydrate(row.slug),
      name: row.name,
      description: row.description,
      status: row.status as 'ACTIVE' | 'INACTIVE',
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

void SERVICE_REPOSITORY;
