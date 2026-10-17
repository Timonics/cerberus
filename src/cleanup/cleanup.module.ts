import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { CLEANUP_REPOSITORY } from './domain/cleanup.port';
import { PrismaCleanupRepository } from './infrastructure/prisma-cleanup.repository';
import { CleanupExpiredRowsUseCase } from './application/cleanup-expired-rows.use-case';
import { CleanupScheduler } from './application/cleanup.scheduler';

/**
 * Cleanup subsystem — owns the retention cron.
 *
 * Imports `PrismaModule` (which is `@Global()`, but Nest still wants
 * the explicit import to surface the dep at compile time). Exports
 * nothing — the use-case is consumed by the scheduler within this
 * module, and the scheduler is auto-registered as a provider.
 *
 * Wiring:
 *   - `PrismaCleanupRepository` is bound to the `CLEANUP_REPOSITORY`
 *     symbol. Tests can override via `Test.createTestingModule` if
 *     they want to skip the real Prisma adapter.
 *   - `CleanupScheduler` runs `OnModuleInit` to register the cron
 *     and `OnModuleDestroy` to clear any pending timer.
 */
@Module({
  imports: [PrismaModule],
  providers: [
    {
      provide: CLEANUP_REPOSITORY,
      useClass: PrismaCleanupRepository,
    },
    CleanupExpiredRowsUseCase,
    CleanupScheduler,
  ],
})
export class CleanupModule {}
