import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import {
  OrganizationDomainRepository,
  OrganizationDomainRow,
} from '../../domain/ports/organization-domain.repository.port';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `OrganizationDomainRepository`.
 *
 * Used by `RegisterUserUseCase` to look up the org from the user's email
 * domain during the public registration form.
 */
@Injectable()
export class PrismaOrganizationDomainRepository extends OrganizationDomainRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findByDomain(
    tx: Tx,
    domain: string,
  ): Promise<OrganizationDomainRow | null> {
    const client = tx as PrismaTx;
    const row = await client.organizationDomain.findUnique({
      where: { domain: domain.toLowerCase() },
    });
    return row
      ? { organizationId: row.organizationId, domain: row.domain }
      : null;
  }
}
