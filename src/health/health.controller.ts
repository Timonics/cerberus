import { Controller, Get } from '@nestjs/common';
import { HealthCheck, HealthCheckService } from '@nestjs/terminus';
import { PostgresHealthIndicator } from './indicators/postgres.indicator';
import { RedisHealthIndicator } from './indicators/redis.indicator';

/**
 * Health endpoints.
 *
 * Two distinct endpoints with distinct semantics:
 *
 *   * `GET /health` — **liveness**. The process is up and the HTTP listener
 *     responds. We deliberately check NO external dependencies: if the
 *     database is down the orchestrator should NOT restart the container,
 *     just take it out of the load balancer (see /ready below).
 *
 *   * `GET /ready`  — **readiness**. All downstream dependencies respond.
 *     Failing this endpoint tells the orchestrator to pull the instance from
 *     the load balancer WITHOUT restarting it.
 *
 * Both endpoints are intentionally excluded from the `/v1` prefix in main.ts.
 */
@Controller()
export class HealthController {
  public constructor(
    private readonly health: HealthCheckService,
    private readonly postgres: PostgresHealthIndicator,
    private readonly redis: RedisHealthIndicator,
  ) {}

  @Get('health')
  public liveness(): {
    status: 'ok';
    timestamp: string;
    uptime: number;
  } {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }

  @Get('ready')
  @HealthCheck()
  public readiness() {
    return this.health.check([
      () => this.postgres.isHealthy('postgres'),
      () => this.redis.isHealthy('redis'),
    ]);
  }
}
