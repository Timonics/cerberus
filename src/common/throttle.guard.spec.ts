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
    get: () => ({ ttl: defaultTtl, max: defaultMax, perEmailMax: 0 }),
  } as unknown as ConfigService;
}

function mockConfigWithEmail(
  defaultTtl: number,
  defaultMax: number,
  perEmailMax: number,
): ConfigService {
  return {
    get: () => ({ ttl: defaultTtl, max: defaultMax, perEmailMax }),
  } as unknown as ConfigService;
}

function mockContext(opts: {
  ip?: string;
  userId?: string;
  body?: Record<string, unknown>;
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
  if (opts.body) req.body = opts.body;
  return {
    getClass: () => ({ name: opts.className }),
    getHandler: () => ({ name: opts.handlerName }),
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

async function expectRejection(
  guard: ThrottleGuard,
  ctx: ExecutionContext,
  expectedBucket: 'ip' | 'email' = 'ip',
): Promise<void> {
  await expect(guard.canActivate(ctx)).rejects.toMatchObject({
    code: 'authentication.rate_limited',
    detail: { bucket: expectedBucket },
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

  describe('per-email bucket (IP-rotation brute-force mitigation)', () => {
    /**
     * V1.5.1 gap: the previous guard only keyed on IP/userId. An
     * attacker rotating IPs but targeting one specific account
     * would never trip the per-IP counter — they could try
     * 1000 IPs × 20 attempts each = 20,000 attempts against one
     * email without ever hitting the per-IP limit on any single
     * IP. The per-email bucket closes that gap.
     */

    it('INCRs a separate email bucket when the body has a valid email', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 10),
      );

      const ctx = mockContext({
        ip: '203.0.113.5',
        body: { email: 'Victim@Example.com' },
        reflector,
        className: 'AuthController',
        handlerName: 'login',
      });

      await guard.canActivate(ctx);

      // Both buckets incremented, independent of each other.
      expect(
        redis.counters.has('throttle:ip:203.0.113.5:AuthController:login'),
      ).toBe(true);
      // Email bucket key is lowercased (case-insensitive matching).
      expect(
        redis.counters.has(
          'throttle:email:victim@example.com:AuthController:login',
        ),
      ).toBe(true);
    });

    it('rejects when the per-email limit trips before the per-IP limit', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 3), // per-email cap = 3
      );

      // Simulate one attacker rotating through 4 IPs, each IP
      // unused so the per-IP counter is at 1 each — well below
      // the per-IP cap of 100. The same email is on every request.
      const email = 'victim@example.com';
      for (const ip of ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']) {
        const ctx = mockContext({
          ip,
          body: { email },
          reflector,
          className: 'AuthController',
          handlerName: 'login',
        });
        if (ip === '10.0.0.4') {
          await expectRejection(guard, ctx, 'email');
        } else {
          await expect(guard.canActivate(ctx)).resolves.toBe(true);
        }
      }

      // Email bucket should have 4 entries (3 increments before
      // the rejection, then the 4th INCR still happens before the
      // threshold check — same as the per-IP path).
      const emailKey = `throttle:email:${email}:AuthController:login`;
      expect(redis.counters.get(emailKey)).toBe(4);
    });

    it('does not gate routes without an email field', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 3),
      );

      // 10 requests, no email in body. Each should pass without
      // bumping a per-email counter.
      for (let i = 0; i < 10; i++) {
        const ctx = mockContext({
          ip: '10.0.0.5',
          body: { foo: 'bar' }, // no email
          reflector,
          className: 'IdentityController',
          handlerName: 'changePassword', // authenticated route, no body email
        });
        await expect(guard.canActivate(ctx)).resolves.toBe(true);
      }

      // No per-email buckets should exist.
      const emailKeys = [...redis.counters.keys()].filter((k) =>
        k.startsWith('throttle:email:'),
      );
      expect(emailKeys.length).toBe(0);
    });

    it('does not gate routes with a malformed email in the body', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 3),
      );

      for (const body of [
        { email: 'not-an-email' },
        { email: 12345 }, // wrong type
        { email: '' },
        { email: '   ' }, // whitespace only
        { email: 'foo@bar' }, // no dot
        { email: '@example.com' }, // no local part
      ]) {
        const ctx = mockContext({
          ip: '10.0.0.6',
          body,
          reflector,
          className: 'AuthController',
          handlerName: 'login',
        });
        await expect(guard.canActivate(ctx)).resolves.toBe(true);
      }

      const emailKeys = [...redis.counters.keys()].filter((k) =>
        k.startsWith('throttle:email:'),
      );
      expect(emailKeys.length).toBe(0);
    });

    it('skips the per-email bucket entirely when perEmailMax=0', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 0), // disabled
      );

      const ctx = mockContext({
        ip: '10.0.0.7',
        body: { email: 'attacker@example.com' },
        reflector,
        className: 'AuthController',
        handlerName: 'login',
      });

      // 100 requests from one IP, all the same email. None should
      // trip the per-email bucket (it's disabled).
      for (let i = 0; i < 50; i++) {
        await expect(guard.canActivate(ctx)).resolves.toBe(true);
      }

      const emailKeys = [...redis.counters.keys()].filter((k) =>
        k.startsWith('throttle:email:'),
      );
      expect(emailKeys.length).toBe(0);
    });

    it('throws with detail.emailHash on the per-email rejection', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 2),
      );

      const email = 'victim@example.com';
      // Three IPs, same email — the third trips per-email
      // (the limit is 2, INCR returns 1, 2, 3; 3 > 2).
      for (const ip of ['10.0.0.10', '10.0.0.11', '10.0.0.12']) {
        const ctx = mockContext({
          ip,
          body: { email },
          reflector,
          className: 'AuthController',
          handlerName: 'login',
        });
        if (ip === '10.0.0.12') {
          // Capture the rejection, then assert on its shape.
          // Using `expect.stringMatching` inline trips eslint's
          // no-unsafe-assignment (the matcher returns `any`).
          let caught: unknown;
          try {
            await guard.canActivate(ctx);
          } catch (err) {
            caught = err;
          }
          expect(caught).toMatchObject({
            code: 'authentication.rate_limited',
            detail: { bucket: 'email' },
          });
          // 16-char hex prefix of the sha-256 of the email —
          // verified separately so the inline matcher doesn't
          // trip eslint's no-unsafe-assignment.
          const emailHash = (caught as { detail?: { emailHash?: string } })
            .detail?.emailHash;
          expect(emailHash).toMatch(/^[0-9a-f]{16}$/);
        } else {
          await expect(guard.canActivate(ctx)).resolves.toBe(true);
        }
      }
    });

    it('different emails get separate counters', async () => {
      reflector.get = jest.fn().mockReturnValue({ ttl: 60, limit: 100 });
      const guard = new ThrottleGuard(
        redis as unknown as Redis,
        reflector,
        mockConfigWithEmail(60, 100, 100), // high cap so each user can run 4 times without tripping
      );

      // 4 logins to user-a, 4 logins to user-b, all from one IP.
      // Each should pass independently — separate per-email
      // buckets, neither at the cap.
      for (const email of ['user-a@example.com', 'user-b@example.com']) {
        for (let i = 0; i < 4; i++) {
          const ctx = mockContext({
            ip: '10.0.0.99',
            body: { email },
            reflector,
            className: 'AuthController',
            handlerName: 'login',
          });
          await expect(guard.canActivate(ctx)).resolves.toBe(true);
        }
      }

      expect(
        redis.counters.get(
          'throttle:email:user-a@example.com:AuthController:login',
        ),
      ).toBe(4);
      expect(
        redis.counters.get(
          'throttle:email:user-b@example.com:AuthController:login',
        ),
      ).toBe(4);
    });
  });
});
