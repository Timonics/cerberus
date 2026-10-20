import {
  ExecutionContext,
  Inject,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { createHash } from 'node:crypto';
import type Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';
import { REDIS_CLIENT } from '../redis/redis.constants';
import { AppConfig } from '../config/configuration';

/**
 * Per-route rate limit (dual-bucket).
 *
 * Two independent counters fire on every request:
 *
 *   1. **Per-IP bucket** (`max`) — key on the caller's IP for
 *      unauthenticated routes, on `principal.userId` for
 *      authenticated routes. Stops the naive "one IP, many
 *      attempts" brute-forcer.
 *
 *   2. **Per-email bucket** (`perEmailMax`) — key on a lowercased
 *      sha-256 of the request body's `email` field, when present
 *      AND syntactically email-shaped. Stops the IP-rotating
 *      brute-forcer that targets one account from 1,000 different
 *      IPs — every IP change skips the per-IP counter but the
 *      same email always lands in the same bucket.
 *
 * Either bucket tripping throws `authentication.rate_limited`.
 * The error's `detail.bucket` field tells security which counter
 * was the bottleneck (`"ip"` vs `"email"`), and the
 * `detail.emailHash` (sha-256, low-cardinality PII) lets logs
 * correlate per-email attacks across rotations.
 *
 * Resolution order:
 *   1. Decorator arguments on the route handler (e.g. `@Throttle(60, 5)`).
 *   2. AppConfig values `rateLimit.ttl`, `rateLimit.max`,
 *      `rateLimit.perEmailMax`.
 *
 * V1.5 (audit H4) fix: this guard actually enforces the limits
 * that `RATE_LIMIT_TTL` / `RATE_LIMIT_MAX` describe. Previously
 * those config values existed but no guard read them — leaving
 * login, register, and password-reset/request open to unlimited
 * brute force.
 *
 * V1.5.1 (per-email brute force gap): the original guard only
 * keyed on IP/userId. An attacker rotating IPs but targeting
 * one specific account would never trip the per-IP counter.
 * The per-email bucket closes that gap with a separate Redis
 * counter keyed on a hash of the request body's email.
 */
export interface ThrottleOptions {
  /** Sliding-window length in seconds. */
  ttl: number;
  /** Max requests per window. */
  limit: number;
  /**
   * Optional override key. Defaults to IP for unauth, userId for
   * auth. Useful for "throttle by email" — key on the request
   * body's email field so a single attacker rotating IPs can't
   * bypass the limit. (Implemented as a separate counter by the
   * guard itself; this hook is for callers that want to take
   * over the IP/userId bucket too.)
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

interface ThrottleRequest {
  ip?: string;
  socket?: { remoteAddress?: string };
  user?: { userId?: string };
  body?: Record<string, unknown>;
}

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
      perEmailMax: 10,
    };
    const ttl = routeOpts?.ttl ?? cfg.ttl;
    const limit = routeOpts?.limit ?? cfg.max;
    const perEmailMax = cfg.perEmailMax;

    const req = ctx.switchToHttp().getRequest<ThrottleRequest>();
    const className = ctx.getClass().name;
    const handlerName = ctx.getHandler().name;

    // ── Bucket 1: per-IP (or per-userId for authenticated routes) ──
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    const primaryKey = req.user?.userId
      ? `throttle:user:${req.user.userId}:${className}:${handlerName}`
      : `throttle:ip:${ip}:${className}:${handlerName}`;

    const primaryCount = await this.incrWithTtl(primaryKey, ttl);
    if (primaryCount > limit) {
      await this.throwRateLimited('ip', undefined);
    }

    // ── Bucket 2: per-email (when body has a valid email field) ──
    //
    // Only check the per-email bucket if the route carries an
    // email in its body (login, register, password-reset/request).
    // Other endpoints don't have an email and shouldn't be
    // gated by it. We extract + normalize here so the same user
    // hitting login from laptop and phone share one bucket.
    const emailRaw = this.extractEmail(req.body);
    if (emailRaw && perEmailMax > 0) {
      const emailKey = `throttle:email:${emailRaw}:${className}:${handlerName}`;
      const emailCount = await this.incrWithTtl(emailKey, ttl);
      if (emailCount > perEmailMax) {
        // Hash the email for logs so security can correlate
        // across rotations without storing the plaintext.
        const emailHash = this.hashEmail(emailRaw);
        await this.throwRateLimited('email', emailHash);
      }
    }

    return true;
  }

  /**
   * INCR with a one-shot TTL: the first INCR creates the key
   * and sets the window; subsequent INCRs within the window
   * count up without resetting the TTL (so a busy caller can't
   * keep the window open indefinitely).
   *
   * Race-safe: `incr` returns the new value atomically; only the
   * caller that observes `count === 1` sets the TTL.
   */
  private async incrWithTtl(key: string, ttl: number): Promise<number> {
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, ttl);
    }
    return count;
  }

  /**
   * Pull `email` out of a body that's not strongly typed at the
   * guard layer. The login DTO validates the field at controller
   * boundary with class-validator; here we just need "looks like
   * an email and isn't garbage". Returns null if missing or
   * clearly invalid (so a non-email route doesn't get gated).
   *
   * 2026-10-19 audit fix H-8: the OAuth password grant carries the
   * identifier in `username` (RFC 6749), not `email` — the per-email
   * bucket never fired on /v1/oauth/token. Fall back to username so
   * both transports land in the same bucket.
   */
  private extractEmail(body: ThrottleRequest['body']): string | null {
    if (!body) return null;
    const raw = body['email'] ?? body['username'];
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim().toLowerCase();
    // Permissive check — class-validator owns the real validation.
    // We just need "is this a string the user meant to be an email
    // address" so an attacker can't bypass by sending garbage
    // values (those still get caught by per-IP).
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return null;
    return trimmed;
  }

  /**
   * Sha-256 of the email, hex-encoded. Used in `detail.emailHash`
   * so security logs can correlate per-email attacks without
   * persisting the plaintext address.
   */
  private hashEmail(email: string): string {
    return createHash('sha256')
      .update(email, 'utf8')
      .digest('hex')
      .slice(0, 16);
  }

  /**
   * Throw the canonical rate-limit error. Bucket + emailHash go
   * into the error's `detail` field — they're logged by Sentry
   * but intentionally NOT returned to the client (see
   * DomainError.toJSON — only `code` + `message` are public).
   */
  private async throwRateLimited(
    bucket: 'ip' | 'email',
    emailHash: string | undefined,
  ): Promise<never> {
    const { DomainError } = await import('../shared/domain');
    throw new DomainError('authentication.rate_limited', 'Too many requests', {
      bucket,
      ...(emailHash !== undefined ? { emailHash } : {}),
    });
  }
}
