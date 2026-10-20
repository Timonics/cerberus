import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { GraphQLError } from 'graphql';
import { createHash } from 'node:crypto';
import { RedisService } from '../../redis/redis.service';
import { GraphqlContext } from '../graphql-context';

/**
 * Global rate limit for the GraphQL transport (audit H-6).
 *
 * Every REST brute-force / spam control (`ThrottleGuard`) was
 * transport-scoped to HTTP routes, so the entire layer was
 * bypassable over `/graphql` — `requestPasswordReset` could
 * email-bomb unthrottled, `register` could burn argon2id CPU, and
 * token-guessing endpoints had no ceiling. This guard closes the
 * gap: it runs on every GraphQL field resolution and enforces
 * per-IP (and where meaningful per-email) Redis counters.
 *
 * Limits (per caller IP, fixed one-minute windows):
 *
 *   * `requestPasswordReset` / `requestEmailVerification` —
 *     5/min/IP PLUS 5/hour per email (the email bucket stops an
 *     IP-rotating attacker targeting one address; for
 *     `requestEmailVerification`, which carries no email argument,
 *     the authenticated user id keys the hour bucket instead).
 *   * `register` — 10/min/IP (mirrors the REST cap).
 *   * all other mutations — 20/min/IP.
 *   * `adminAuditLog` — 30/min/IP (the heaviest query: bounded
 *     user-org resolution per row).
 *   * all other queries — 60/min/IP.
 *
 * Register as an APP_GUARD; it no-ops on non-GraphQL contexts.
 * Redis failures fail OPEN (logged loudly) — a down cache must not
 * take down the API, and the REST layer applies the same posture.
 */
@Injectable()
export class GraphqlThrottleGuard implements CanActivate {
  private readonly logger = new Logger(GraphqlThrottleGuard.name);

  public constructor(private readonly redis: RedisService) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType<string>() !== 'graphql') {
      return true;
    }
    const gqlContext = GqlExecutionContext.create(context);
    const info = gqlContext.getInfo<{
      fieldName: string;
      parentType: { name: string };
    }>();
    const opName = info.fieldName;
    const isMutation = info.parentType.name === 'Mutation';
    const limit = this.limitFor(opName, isMutation);
    if (limit === null) {
      return true;
    }

    const httpContext = gqlContext.getContext<GraphqlContext>();
    const req = httpContext.req;
    const ip = req.ip ?? req.socket?.remoteAddress ?? 'unknown';
    const minuteBucket = Math.floor(Date.now() / 60_000);

    const ipCount = await this.incrWithTtl(
      `gql:throttle:ip:${ip}:${opName}:${minuteBucket}`,
      120,
    );
    if (ipCount > limit.perMinute) {
      throw this.rateLimited('ip', opName);
    }

    if (limit.perEmailHour !== undefined) {
      const emailKey =
        this.extractEmail(gqlContext.getArgs()) ??
        httpContext.currentUser?.sub ??
        null;
      if (emailKey) {
        const hourBucket = Math.floor(Date.now() / 3_600_000);
        const digest = createHash('sha256')
          .update(emailKey.trim().toLowerCase(), 'utf8')
          .digest('hex')
          .slice(0, 16);
        const emailCount = await this.incrWithTtl(
          `gql:throttle:email:${digest}:${opName}:${hourBucket}`,
          7_200,
        );
        if (emailCount > limit.perEmailHour) {
          throw this.rateLimited('email', opName);
        }
      }
    }
    return true;
  }

  private limitFor(
    opName: string,
    isMutation: boolean,
  ): { perMinute: number; perEmailHour?: number } | null {
    if (
      opName === 'requestPasswordReset' ||
      opName === 'requestEmailVerification'
    ) {
      return { perMinute: 5, perEmailHour: 5 };
    }
    if (opName === 'register') {
      return { perMinute: 10 };
    }
    if (isMutation) {
      return { perMinute: 20 };
    }
    if (opName === 'adminAuditLog') {
      return { perMinute: 30 };
    }
    return { perMinute: 60 };
  }

  /**
   * INCR with a one-shot TTL (same pattern as the REST
   * ThrottleGuard): the first increment creates the key and sets
   * the window; later increments in the window count up without
   * resetting it. Keys carry an explicit wall-clock bucket so
   * windows are self-aligning; the TTL is just garbage collection.
   */
  private async incrWithTtl(key: string, ttl: number): Promise<number> {
    try {
      const client = this.redis.getClient();
      const count = await client.incr(key);
      if (count === 1) {
        await client.expire(key, ttl);
      }
      return count;
    } catch (err) {
      this.logger.error(
        `GraphQL throttle Redis failure (failing open): ${String(err)}`,
      );
      return 0;
    }
  }

  /**
   * Find an `email` argument anywhere in the GraphQL args tree
   * (e.g. `{ input: { email } }`). Returns null when absent so
   * email-less operations only get the per-IP bucket.
   */
  private extractEmail(args: unknown): string | null {
    if (args === null || typeof args !== 'object') return null;
    for (const [key, value] of Object.entries(args)) {
      if (key === 'email' && typeof value === 'string') {
        const trimmed = value.trim().toLowerCase();
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return trimmed;
      }
      if (value !== null && typeof value === 'object') {
        const nested = this.extractEmail(value);
        if (nested) return nested;
      }
    }
    return null;
  }

  private rateLimited(bucket: 'ip' | 'email', opName: string): GraphQLError {
    this.logger.warn(
      `GraphQL rate limit tripped (bucket=${bucket}, operation=${opName})`,
    );
    return new GraphQLError('Too many requests', {
      extensions: { code: 'RATE_LIMITED' },
    });
  }
}
