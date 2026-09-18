import { Injectable } from '@nestjs/common';
import {
  HealthIndicatorResult,
  HealthIndicatorService,
} from '@nestjs/terminus';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * Postgres readiness indicator.
 *
 * Performs a trivial `SELECT 1` round-trip. We use the raw client rather
 * than the Prisma query builder because we want the absolute minimum
 * overhead per probe (kubelet / load balancer will call this every few
 * seconds).
 *
 * The PrismaClient extends `$queryRawUnsafe` so we can issue the statement
 * directly. The query is parameter-less so there is no injection risk.
 */
@Injectable()
export class PostgresHealthIndicator {
  public constructor(
    private readonly healthIndicatorService: HealthIndicatorService,
    private readonly prisma: PrismaService,
  ) {}

  /** Report the database as up if a SELECT 1 round-trip succeeds. */
  public async isHealthy(key: string): Promise<HealthIndicatorResult> {
    const indicator = this.healthIndicatorService.check(key);
    const start = Date.now();
    try {
      // $queryRawUnsafe with a literal "1" — no user input flows here.
      await this.prisma.$queryRawUnsafe('SELECT 1');
      return indicator.up({ responseTimeMs: Date.now() - start });
    } catch (err) {
      return indicator.down({
        message: err instanceof Error ? err.message : 'unknown error',
        responseTimeMs: Date.now() - start,
      });
    }
  }
}
