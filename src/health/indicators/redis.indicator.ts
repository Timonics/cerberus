import { Injectable } from '@nestjs/common';
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
      return indicator.down({
        message: err instanceof Error ? err.message : 'unknown error',
        responseTimeMs: Date.now() - start,
      });
    }
  }
}
