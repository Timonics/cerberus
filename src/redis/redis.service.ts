import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
} from '@nestjs/common';
import type Redis from 'ioredis';
import { REDIS_CLIENT } from './redis.constants';

/**
 * Thin wrapper around the ioredis client.
 *
 * Why a wrapper?
 *
 *   * Owns the connection lifecycle (close cleanly on SIGTERM).
 *   * Logs reconnect events at warn level — silent reconnects hide real
 *     production issues.
 *   * Exposes only the verbs we actually use (`get`, `set`, `del`,
 *     `expire`, `eval`, `ping`). Anything else belongs behind a more
 *     specific port (e.g. login-attempt repository, rate-limit repository).
 *
 * IMPORTANT: This class is part of the infrastructure layer. Use-cases and
 * domain code MUST NOT inject it directly — they go through a port
 * (e.g. `LoginAttemptRepository`) backed by this client.
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);

  public constructor(@Inject(REDIS_CLIENT) private readonly client: Redis) {
    this.client.on('connect', () => this.logger.log('Redis connected'));
    this.client.on('reconnecting', () =>
      this.logger.warn('Redis reconnecting'),
    );
    this.client.on('error', (err: Error) =>
      this.logger.error(`Redis error: ${err.message}`, err.stack),
    );
  }

  /** Expose the raw client to other infrastructure-layer adapters. */
  public getClient(): Redis {
    return this.client;
  }

  /** Cheap round-trip used by the readiness probe. */
  public async ping(): Promise<void> {
    const pong = await this.client.ping();
    if (pong !== 'PONG') {
      throw new Error(`Unexpected Redis PING response: ${String(pong)}`);
    }
  }

  public async onModuleDestroy(): Promise<void> {
    await this.client.quit();
    this.logger.log('Redis disconnected');
  }
}
