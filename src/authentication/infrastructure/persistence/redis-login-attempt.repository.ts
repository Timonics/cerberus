import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type Redis from 'ioredis';
import {
  LoginAttemptRepository,
  LoginAttemptWindow,
} from '../../domain/ports/login-attempt.repository.port';
import { RedisService } from '../../../redis/redis.service';

/**
 * Redis-backed sliding-window login-attempt counter.
 *
 * Storage:
 *   key   = `cerberus:login_attempts:{email}:{ip}` (sorted set)
 *   key   = `cerberus:login_attempts:{email}:account` — per-email
 *           cumulative counter across ALL IPs (audit fix H-8)
 *   key   = `cerberus:login_attempts:{email}:mfa_pending` — count of
 *           MFA-pending challenge issuances (audit fix H-12)
 *   score = epoch milliseconds
 *   value = `{score}:{randomHex}` (uniqueness only — we don't read it)
 *
 * On every `recordFailure`:
 *   1. ZADD with the current timestamp
 *   2. ZREMRANGEBYSCORE to evict entries older than `now - windowSeconds`
 *   3. ZCARD to get the resulting size
 *   4. EXPIRE on the key so it auto-cleans when there's no activity
 *
 * Done as a MULTI / pipeline transaction so the count we return is
 * consistent with what other concurrent readers see.
 */
@Injectable()
export class RedisLoginAttemptRepository extends LoginAttemptRepository {
  public constructor(private readonly redis: RedisService) {
    super();
  }

  private get client(): Redis {
    return this.redis.getClient();
  }

  public async recordFailure(
    email: string,
    ip: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow> {
    const key = this.keyFor(email, ip);
    const cutoff = now.getTime() - windowSeconds * 1000;
    const score = now.getTime();
    const member = `${score}:${randomBytes(8).toString('hex')}`;

    const pipeline = this.client.multi();
    pipeline.zadd(key, score, member);
    pipeline.zremrangebyscore(key, '-inf', `(${cutoff}`);
    pipeline.zcard(key);
    pipeline.expire(key, windowSeconds * 2); // keep key around a bit longer than window
    const results = await pipeline.exec();

    const count = (results?.[2]?.[1] as number) ?? 0;

    return {
      count,
      lastFailureAt: count > 0 ? now : null,
    };
  }

  public async clear(email: string, ip: string): Promise<void> {
    await this.client.del(this.keyFor(email, ip));
  }

  public async getWindow(
    email: string,
    ip: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow> {
    const key = this.keyFor(email, ip);
    const cutoff = now.getTime() - windowSeconds * 1000;
    const pipeline = this.client.multi();
    pipeline.zremrangebyscore(key, '-inf', `(${cutoff}`);
    pipeline.zcard(key);
    pipeline.zrange(key, -1, -1, 'WITHSCORES');
    const results = await pipeline.exec();
    const count = (results?.[1]?.[1] as number) ?? 0;
    const lastEntry = results?.[2]?.[1] as string[] | undefined;
    const lastScore =
      lastEntry && lastEntry.length >= 2 ? Number(lastEntry[1]) : null;
    return {
      count,
      lastFailureAt:
        lastScore !== null && !Number.isNaN(lastScore)
          ? new Date(lastScore)
          : null,
    };
  }

  public async recordAccountFailure(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow> {
    const key = this.accountKeyFor(email);
    const cutoff = now.getTime() - windowSeconds * 1000;
    const score = now.getTime();
    const member = `${score}:${randomBytes(8).toString('hex')}`;

    const pipeline = this.client.multi();
    pipeline.zadd(key, score, member);
    pipeline.zremrangebyscore(key, '-inf', `(${cutoff}`);
    pipeline.zcard(key);
    pipeline.expire(key, windowSeconds * 2);
    const results = await pipeline.exec();

    const count = (results?.[2]?.[1] as number) ?? 0;
    return {
      count,
      lastFailureAt: count > 0 ? now : null,
    };
  }

  public async getAccountWindow(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow> {
    const key = this.accountKeyFor(email);
    const cutoff = now.getTime() - windowSeconds * 1000;
    const pipeline = this.client.multi();
    pipeline.zremrangebyscore(key, '-inf', `(${cutoff}`);
    pipeline.zcard(key);
    pipeline.zrange(key, -1, -1, 'WITHSCORES');
    const results = await pipeline.exec();
    const count = (results?.[1]?.[1] as number) ?? 0;
    const lastEntry = results?.[2]?.[1] as string[] | undefined;
    const lastScore =
      lastEntry && lastEntry.length >= 2 ? Number(lastEntry[1]) : null;
    return {
      count,
      lastFailureAt:
        lastScore !== null && !Number.isNaN(lastScore)
          ? new Date(lastScore)
          : null,
    };
  }

  public async clearAccount(email: string): Promise<void> {
    await this.client.del(this.accountKeyFor(email));
  }

  public async recordMfaPendingIssuance(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<number> {
    const key = `cerberus:login_attempts:${email.toLowerCase()}:mfa_pending`;
    const cutoff = now.getTime() - windowSeconds * 1000;
    const score = now.getTime();
    const member = `${score}:${randomBytes(8).toString('hex')}`;

    const pipeline = this.client.multi();
    pipeline.zadd(key, score, member);
    pipeline.zremrangebyscore(key, '-inf', `(${cutoff}`);
    pipeline.zcard(key);
    pipeline.expire(key, windowSeconds * 2);
    const results = await pipeline.exec();

    return (results?.[2]?.[1] as number) ?? 0;
  }

  private keyFor(email: string, ip: string): string {
    // Lowercase the email for key stability — emails are case-insensitive
    // and we don't want the same user producing two windows.
    return `cerberus:login_attempts:${email.toLowerCase()}:${ip}`;
  }

  private accountKeyFor(email: string): string {
    // H-8: the any-IP bucket. Same lowercasing rule as keyFor.
    return `cerberus:login_attempts:${email.toLowerCase()}:account`;
  }
}
