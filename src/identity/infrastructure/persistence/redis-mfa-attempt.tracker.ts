import { Injectable } from '@nestjs/common';
import { RedisService } from '../../../redis/redis.service';
import {
  MFA_ATTEMPT_TRACKER,
  MfaAttemptTracker,
} from '../../domain/ports/mfa-attempt-tracker.port';

/**
 * Redis-backed `MfaAttemptTracker`.
 *
 * Keys:
 *   * `mfa:fail:{userId}:{sessionId}` — INCR counter, EXPIRE set on
 *     the first increment (sliding window, same pattern as the
 *     throttle guard).
 *   * `mfa:lock:{userId}:{sessionId}` — SET EX, present for the
 *     duration of the lockout.
 */
@Injectable()
export class RedisMfaAttemptTracker extends MfaAttemptTracker {
  private static readonly WINDOW_SECONDS = 15 * 60; // sliding failure window

  public constructor(private readonly redis: RedisService) {
    super();
  }

  public async isLocked(userId: string, sessionId: string): Promise<boolean> {
    const val = await this.redis
      .getClient()
      .get(`mfa:lock:${userId}:${sessionId}`);
    return val !== null;
  }

  public async recordFailure(
    userId: string,
    sessionId: string,
  ): Promise<number> {
    const key = `mfa:fail:${userId}:${sessionId}`;
    const count = await this.redis.getClient().incr(key);
    if (count === 1) {
      await this.redis
        .getClient()
        .expire(key, RedisMfaAttemptTracker.WINDOW_SECONDS);
    }
    return count;
  }

  public async lock(
    userId: string,
    sessionId: string,
    ttlSeconds: number,
  ): Promise<void> {
    await this.redis
      .getClient()
      .set(`mfa:lock:${userId}:${sessionId}`, '1', 'EX', ttlSeconds);
  }

  public async clearFailures(userId: string, sessionId: string): Promise<void> {
    await this.redis.getClient().del(`mfa:fail:${userId}:${sessionId}`);
  }
}

// Re-export so module files can import the token from the adapter's
// module path if they prefer (matches the prisma-repo convention).
export { MFA_ATTEMPT_TRACKER };
