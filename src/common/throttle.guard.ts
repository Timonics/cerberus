import {
  ExecutionContext,
  Inject,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';
import { REDIS_CLIENT } from '../redis/redis.constants';
import { AppConfig } from '../config/configuration';

/**
 * Per-route rate limit.
 *
 * Two axes:
 *   * `ttl` — sliding window length in seconds (default: env-driven).
 *   * `limit` — max requests per window (default: env-driven).
 *
 * Resolution order:
 *   1. Decorator arguments on the route handler (e.g. `@Throttle(60, 5)`).
 *   2. AppConfig values `rateLimit.ttl` and `rateLimit.max`.
 *
 * The guard keys on the caller's IP for unauthenticated routes, and
 * `principal.userId` for authenticated routes (if `@CurrentUser()`
 * has been resolved by the time the guard runs — typically via
 * JwtAuthGuard running BEFORE this guard).
 *
 * V1.5 (audit H4) fix: this guard actually enforces the limits that
 * `RATE_LIMIT_TTL` and `RATE_LIMIT_MAX` describe. Previously those
 * config values existed but no guard read them — leaving login,
 * register, and password-reset/request open to unlimited brute force.
 */
export interface ThrottleOptions {
  /** Sliding-window length in seconds. */
  ttl: number;
  /** Max requests per window. */
  limit: number;
  /**
   * Optional override key. Defaults to IP for unauth, userId for auth.
   * Useful for "throttle by email" — key on the request body's email
   * field so a single attacker rotating IPs can't bypass the limit.
   */
  keyBy?: (req: unknown) => string;
}

/**
 * Decorator: mark a controller method as rate-limited. Without
 * arguments, falls back to AppConfig.rateLimit.ttl/max.
 */
export const THROTTLE_METADATA = 'cerberus:throttle-options';
export const Throttle = (ttl?: number, limit?: number): MethodDecorator =>
  SetMetadata(THROTTLE_METADATA, { ttl, limit });

@Injectable()
export class ThrottleGuard {
  public constructor(
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    private readonly reflector: Reflector,
    private readonly config: ConfigService,
  ) {}

  public async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const routeOpts = this.reflector.get<
      | {
          ttl?: number;
          limit?: number;
        }
      | undefined
    >(THROTTLE_METADATA, ctx.getHandler());

    const cfg = this.config.get<AppConfig['rateLimit']>('rateLimit') ?? {
      ttl: 60,
      max: 60,
    };
    const ttl = routeOpts?.ttl ?? cfg.ttl;
    const limit = routeOpts?.limit ?? cfg.max;

    const req = ctx.switchToHttp().getRequest<{
      ip?: string;
      socket?: { remoteAddress?: string };
      user?: { userId?: string };
      body?: Record<string, unknown>;
    }>();
    // Resolve the bucket key. Authenticated → userId; else IP.
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    const key = req.user?.userId
      ? `throttle:user:${req.user.userId}:${ctx.getClass().name}:${ctx.getHandler().name}`
      : `throttle:ip:${ip}:${ctx.getClass().name}:${ctx.getHandler().name}`;

    // Sliding window via INCR + EXPIRE. The first INCR returns 1 and we
    // set the TTL; subsequent INCRs within the TTL return 2, 3, …
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, ttl);
    }
    if (count > limit) {
      // Don't throw a generic exception — the DomainErrorFilter maps
      // the rate-limited error to a 429 with the standard error envelope.
      const { DomainError } = await import('../shared/domain');
      throw new DomainError(
        'authentication.rate_limited',
        'Too many requests',
        { retryAfterSeconds: ttl },
      );
    }
    return true;
  }
}
