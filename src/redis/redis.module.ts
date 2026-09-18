import { Global, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { AppConfig } from '../config/configuration';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';

/**
 * Redis infrastructure module.
 *
 * `useFactory` constructs the ioredis client once at boot. The factory is
 * async-safe; we don't actually need to await anything, but `forRootAsync`
 * supports it.
 *
 * Connection options are conservative: at most 3 retries per request, fail
 * fast rather than hang. `lazyConnect: false` because we want to surface
 * connection errors at boot, not at first request.
 */
@Global()
@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [ConfigService],
      useFactory: (config: ConfigService): Redis => {
        const url = config.getOrThrow<AppConfig['redis']['url']>('redis.url');
        return new Redis(url, {
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: false,
        });
      },
    },
    RedisService,
  ],
  exports: [RedisService],
})
export class RedisModule {}
