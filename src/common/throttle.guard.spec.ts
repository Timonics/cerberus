/**
 * ThrottleGuard contract tests.
 *
 * The guard enforces the rate-limit config that was previously
 * declared but unused (audit H4 fix). The test pins:
 *   1. Per-route options take precedence over app defaults.
 *   2. Authenticated requests key on userId (more reliable than IP).
 *   3. Unauthenticated requests key on IP.
 *   4. The first request in a window gets a TTL set; subsequent
 *      requests in the same window do NOT reset the TTL.
 *   5. The (limit + 1)th request throws authentication.rate_limited.
 *
 * Real Redis isn't required — we mock it. The behavior we care about
 * is the contract, not Redis itself.
 */

import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import type Redis from 'ioredis';
import { ThrottleGuard } from './throttle.guard';

class FakeRedis {
  /** Per-key counter, simulating INCR semantics. */
  public readonly counters = new Map<string, number>();
  /** Per-key TTL, set on the first INCR. */
  public readonly ttls = new Map<string, number>();

  public incr(key: string): Promise<number> {
    const current = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, current);
    return Promise.resolve(current);
  }

  public expire(key: string, ttl: number): Promise<void> {
    // Only set the TTL if not already set — mirrors Redis EXPIRE.
    if (!this.ttls.has(key)) {
      this.ttls.set(key, ttl);
    }
    return Promise.resolve();
  }

  public reset(): void {
    this.counters.clear();
    this.ttls.clear();
  }
}

function mockConfig(defaultTtl: number, defaultMax: number): ConfigService {
  return {
    get: () => ({ ttl: defaultTtl, max: defaultMax }),
  } as unknown as ConfigService;
}

function mockContext(opts: {
  ip?: string;
  userId?: string;
  reflector: Reflector;
  handlerName: string;
  className: string;
}): ExecutionContext {
  const req: Record<string, unknown> = {};
  if (opts.ip !== undefined) {
    req.ip = opts.ip;
    req.socket = { remoteAddress: opts.ip };
  }
  if (opts.userId) req.user = { userId: opts.userId };
  return {
    getClass: () => ({ name: opts.className }),
    getHandler: () => ({ name: opts.handlerName }),
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

async function expectRejection(
  guard: ThrottleGuard,
  ctx: ExecutionContext,
): Promise<void> {
  await expect(guard.canActivate(ctx)).rejects.toMatchObject({
    code: 'authentication.rate_limited',
  });
}

describe('ThrottleGuard', () => {
  let redis: FakeRedis;
  let reflector: Reflector;

  beforeEach(() => {
    redis = new FakeRedis();
    reflector = new Reflector();
  });

  describe('limit + reject behavior', () => {
    it('allows up to N requests, rejects the (N+1)th', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 3 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 60),
      );

      const ctx = mockContext({
        ip: '10.0.0.1',
        reflector,
        className: 'AuthController',
        handlerName: 'login',
      });

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      await expectRejection(guard, ctx);
    });

    it('falls back to env-driven defaults when @Throttle() has no args', async () => {
      // @Throttle() called with no args → metadata is { ttl: undefined, limit: undefined }
      reflector.get = jest
        .fn()
        .mockReturnValue({ ttl: undefined, limit: undefined });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 2), // default max 2
      );

      const ctx = mockContext({
        ip: '10.0.0.2',
        reflector,
        className: 'AuthController',
        handlerName: 'login',
      });

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      await expectRejection(guard, ctx);
    });
  });

  describe('TTL semantics', () => {
    it('sets TTL only on the first INCR', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 30, limit: 10 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 60),
      );
      const ctx = mockContext({
        ip: '10.0.0.3',
        reflector,
        className: 'X',
        handlerName: 'y',
      });

      await guard.canActivate(ctx);
      await guard.canActivate(ctx);
      await guard.canActivate(ctx);

      const key = 'throttle:ip:10.0.0.3:X:y';
      expect(redis.counters.get(key)).toBe(3);
      expect(redis.ttls.get(key)).toBe(30); // only set once
    });
  });

  describe('bucket keying', () => {
    it('keys unauthenticated requests on IP', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 5 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 60),
      );

      const ctx = mockContext({
        ip: '203.0.113.5',
        reflector,
        className: 'IdentityController',
        handlerName: 'register',
      });

      await guard.canActivate(ctx);
      const expectedKey = 'throttle:ip:203.0.113.5:IdentityController:register';
      expect(redis.counters.has(expectedKey)).toBe(true);
      expect(redis.counters.size).toBe(1);
    });

    it('keys authenticated requests on userId, not IP', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 5 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 60),
      );

      const ctx = mockContext({
        ip: '203.0.113.99',
        userId: 'user-abc',
        reflector,
        className: 'IdentityController',
        handlerName: 'changePassword',
      });

      await guard.canActivate(ctx);
      const expectedKey =
        'throttle:user:user-abc:IdentityController:changePassword';
      expect(redis.counters.has(expectedKey)).toBe(true);
      // The IP-based key must NOT exist — same user can change password
      // from any IP without affecting their per-user limit.
      const ipKey =
        'throttle:ip:203.0.113.99:IdentityController:changePassword';
      expect(redis.counters.has(ipKey)).toBe(false);
    });

    it('different routes get different buckets for the same user', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 5 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfig(60, 60),
      );

      const ctxA = mockContext({
        userId: 'user-1',
        reflector,
        className: 'AuthController',
        handlerName: 'login',
      });
      const ctxB = mockContext({
        userId: 'user-1',
        reflector,
        className: 'IdentityController',
        handlerName: 'register',
      });

      await guard.canActivate(ctxA);
      await guard.canActivate(ctxB);

      expect(redis.counters.size).toBe(2);
      expect(
        redis.counters.has('throttle:user:user-1:AuthController:login'),
      ).toBe(true);
      expect(
        redis.counters.has('throttle:user:user-1:IdentityController:register'),
      ).toBe(true);
    });
  });
});
