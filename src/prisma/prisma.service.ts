import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * In test (jest), every suite boots its own Nest application, and each
 * application would otherwise spawn and dispose its own query engine.
 * Rapid spawn/disconnect churn across 26 suites is a known source of
 * flaky `Engine is not yet connected` / `Response from the Engine was
 * empty` failures on CI runners. So in test we share ONE client per
 * worker process (via globalThis, which survives jest's module reset
 * between test files) and never disconnect it mid-run — the worker
 * process exit reaps the engine. Production behavior is unchanged.
 */
const globalForPrisma = globalThis as unknown as {
  cerberusPrismaClient?: PrismaClient;
};

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
  public constructor() {
    super();
    // Returning the shared instance from the constructor makes every
    // Nest application in the jest worker reuse one engine. Prisma
    // reconnects lazily, so a client left over from a previous suite
    // is fine. In production this branch never runs.
    if (process.env.NODE_ENV === 'test') {
      if (!globalForPrisma.cerberusPrismaClient) {
        globalForPrisma.cerberusPrismaClient = this;
      }
      return globalForPrisma.cerberusPrismaClient as PrismaService;
    }
  }

  public async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  public async onModuleDestroy(): Promise<void> {
    if (process.env.NODE_ENV === 'test') {
      // The client is shared across suites in this worker — disconnecting
      // here would break every later suite (and rapid connect/disconnect
      // cycles are what cause the engine flakiness this guards against).
      return;
    }
    // `$disconnect()` is idempotent and returns once the pool has drained.
    // Nest calls this on SIGTERM/SIGINT because we enabled shutdown hooks
    // in `main.ts`.
    await this.$disconnect();
  }
}
