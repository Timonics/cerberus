import { randomBytes } from 'node:crypto';
import { Clock, DomainError } from '../../../shared/domain';

/**
 * An API key owned by an App.
 *
 * Same shape as AdminApiKey but bound to an `App` rather than to an
 * admin operator. Plaintext is generated once at issue time and never
 * persisted — only the argon2id hash is stored.
 */
export class AppApiKey {
  private constructor(
    public readonly id: string,
    public readonly appId: string,
    public readonly keyHash: string,
    public readonly name: string,
    public readonly createdAt: Date,
    public readonly lastUsedAt: Date | null,
    public readonly expiresAt: Date,
    public readonly revokedAt: Date | null,
  ) {}

  public static issue(params: {
    id: string;
    appId: string;
    plaintextToken: string;
    keyHash: string;
    name: string;
    clock: Clock;
    ttlSeconds: number;
  }): AppApiKey {
    const now = params.clock.now();
    const expiresAt = new Date(now.getTime() + params.ttlSeconds * 1000);
    if (expiresAt.getTime() <= now.getTime()) {
      throw new DomainError(
        'app.api_key.ttl_non_positive',
        'App API key TTL must be positive',
      );
    }
    // Suppress unused-arg lint — the plaintext is intentionally NOT
    // stored in the aggregate; the use-case returns it separately.
    void params.plaintextToken;
    return new AppApiKey(
      params.id,
      params.appId,
      params.keyHash,
      params.name.trim(),
      now,
      null,
      expiresAt,
      null,
    );
  }

  public static fromPersistence(params: {
    id: string;
    appId: string;
    keyHash: string;
    name: string;
    createdAt: Date;
    lastUsedAt: Date | null;
    expiresAt: Date;
    revokedAt: Date | null;
  }): AppApiKey {
    return new AppApiKey(
      params.id,
      params.appId,
      params.keyHash,
      params.name,
      params.createdAt,
      params.lastUsedAt,
      params.expiresAt,
      params.revokedAt,
    );
  }

  public revoke(clock: Clock): AppApiKey {
    if (this.revokedAt !== null) return this;
    return new AppApiKey(
      this.id,
      this.appId,
      this.keyHash,
      this.name,
      this.createdAt,
      this.lastUsedAt,
      this.expiresAt,
      clock.now(),
    );
  }

  public markUsed(clock: Clock): AppApiKey {
    return new AppApiKey(
      this.id,
      this.appId,
      this.keyHash,
      this.name,
      this.createdAt,
      clock.now(),
      this.expiresAt,
      this.revokedAt,
    );
  }

  public isAliveAt(when: Date): boolean {
    if (this.revokedAt !== null) return false;
    if (this.expiresAt.getTime() <= when.getTime()) return false;
    return true;
  }
}

void randomBytes;
