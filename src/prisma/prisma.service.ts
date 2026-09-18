import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * Thin Prisma client wrapper.
 *
 * We do not extend `PrismaClient` with helper methods — those belong in the
 * repository adapters of each bounded context. This service exists solely to
 *
 *   * own the singleton client lifecycle (connect on boot, disconnect on
 *     shutdown so SIGTERM drains cleanly),
 *   * be the only place `new PrismaClient()` is called,
 *   * give us a single seam if we ever need to swap ORMs (Drizzle, Kysely) —
 *     repositories inject this service, not `PrismaClient` directly.
 *
 * Repositories SHOULD depend on `PrismaService` (the concrete class) so the
 * generated `PrismaClient` types propagate through the type system without
 * extra wiring. Domain code NEVER imports this.
 */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  public async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  public async onModuleDestroy(): Promise<void> {
    // `$disconnect()` is idempotent and returns once the pool has drained.
    // Nest calls this on SIGTERM/SIGINT because we enabled shutdown hooks
    // in `main.ts`.
    await this.$disconnect();
  }
}
