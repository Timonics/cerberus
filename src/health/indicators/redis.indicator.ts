import { Injectable, Logger } from '@nestjs/common';
import {
  HealthIndicatorResult,
  HealthIndicatorService,
} from '@nestjs/terminus';
import { RedisService } from '../../redis/redis.service';

/**
 * Redis readiness indicator.
 *
 * Issues a `PING` and asserts the response is `PONG`. Uses the ioredis
 * client owned by RedisService — we never open a second connection just for
 * the probe.
 */
@Injectable()
export class RedisHealthIndicator {
  private readonly logger = new Logger(RedisHealthIndicator.name);

  public constructor(
    private readonly healthIndicatorService: HealthIndicatorService,
    private readonly redis: RedisService,
  ) {}

  public async isHealthy(key: string): Promise<HealthIndicatorResult> {
    const indicator = this.healthIndicatorService.check(key);
    const start = Date.now();
    try {
      await this.redis.ping();
      return indicator.up({ responseTimeMs: Date.now() - start });
    } catch (err) {
      // /ready is unauthenticated — same rule as the Postgres
      // indicator: no raw driver error strings in the response body.
      this.logger.error(
        `Redis readiness probe failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return indicator.down({
        message: 'cache unreachable',
        responseTimeMs: Date.now() - start,
      });
    }
  }
}
