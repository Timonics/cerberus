import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  CLEANUP_REPOSITORY,
  CleanupRepository,
  CleanupResult,
  CleanupTtls,
} from '../domain/cleanup.port';

/**
 * Run a single cleanup pass against the configured retention policy.
 *
 * The use-case is a thin orchestration layer over `CleanupRepository`:
 * the actual deletes live in the Prisma adapter because they touch
 * tables across every bounded context (engagement, identity,
 * authentication, authorization, apps, administration). Keeping the
 * use-case framework-agnostic makes it testable without booting
 * the Prisma graph (mock `CleanupRepository`).
 *
 * Failures are caught at the table level inside the adapter; the
 * use-case itself never throws. The scheduler logs the result.
 */
@Injectable()
export class CleanupExpiredRowsUseCase {
  private readonly logger = new Logger(CleanupExpiredRowsUseCase.name);

  public constructor(
    @Inject(CLEANUP_REPOSITORY)
    private readonly repo: CleanupRepository,
  ) {}

  public async execute(ttls: CleanupTtls): Promise<CleanupResult> {
    const result = await this.repo.cleanup(ttls);
    this.logger.log(
      `cleanup pass complete — ${Object.entries(result.deleted)
        .map(([table, count]) => `${table}=${count}`)
        .join(', ')} (${result.durationMs}ms)`,
    );
    return result;
  }
}
