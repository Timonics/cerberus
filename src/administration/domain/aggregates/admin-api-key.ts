import { randomBytes } from 'node:crypto';
import { Clock, DomainError } from '../../../shared/domain';
import { AdminRole, AdminRoleLiteral } from '../value-objects/admin-role';

/**
 * An admin API key.
 *
 * Lifecycle:
 *   * `issue()` — operator calls this through
 *     `IssueAdminApiKeyUseCase`. A random 32-byte token is generated,
 *     argon2id-hashed, the plaintext token is returned exactly once,
 *     and the aggregate is persisted with the hash.
 *   * `verify()` — called on every admin request. Re-hashes the
 *     presented plaintext with argon2id and constant-time-compares
 *     against `this.keyHash`.
 *   * `markUsed()` — updated on every successful verification to
 *     support audit + last-used-at dashboards.
 *   * `revoke()` — soft-revokes (sets `revokedAt`). Future `verify()`
 *     calls return false.
 *   * `isAliveAt(when)` — composite check used by the repository
 *     lookup: revoked AND expired keys are filtered out.
 *
 * Plaintext tokens are NEVER persisted. The argon2id hash is
 * `String`-typed and stored as `VARCHAR(255)` to fit argon2id's
 * default encoded representation ($argon2id$v=19$m=...).
 */
export class AdminApiKey {
  private constructor(
    public readonly id: string,
    public readonly name: string,
    public readonly keyHash: string,
    public readonly role: AdminRole,
    public readonly createdAt: Date,
    public readonly createdBy: string,
    public readonly lastUsedAt: Date | null,
    public readonly expiresAt: Date,
    public readonly revokedAt: Date | null,
    public readonly notes: string | null,
  ) {}

  public static issue(params: {
    id: string;
    name: string;
    plaintextToken: string;
    keyHash: string;
    role: AdminRoleLiteral;
    createdBy: string;
    clock: Clock;
    ttlSeconds: number;
    notes?: string;
  }): AdminApiKey {
    const now = params.clock.now();
    const expiresAt = new Date(now.getTime() + params.ttlSeconds * 1000);
    if (expiresAt.getTime() <= now.getTime()) {
      throw new DomainError(
        'admin.api_key.ttl_non_positive',
        'Admin API key TTL must be positive',
      );
    }
    // Suppress unused-arg lint — the plaintext is intentionally NOT
    // stored in the aggregate; the use-case returns it separately.
    void params.plaintextToken;
    return new AdminApiKey(
      params.id,
      params.name.trim(),
      params.keyHash,
      AdminRole.create(params.role),
      now,
      params.createdBy.trim(),
      null,
      expiresAt,
      null,
      params.notes?.trim() ?? null,
    );
  }

  public static fromPersistence(params: {
    id: string;
    name: string;
    keyHash: string;
    role: string;
    createdAt: Date;
    createdBy: string;
    lastUsedAt: Date | null;
    expiresAt: Date;
    revokedAt: Date | null;
    notes: string | null;
  }): AdminApiKey {
    return new AdminApiKey(
      params.id,
      params.name,
      params.keyHash,
      AdminRole.rehydrate(params.role),
      params.createdAt,
      params.createdBy,
      params.lastUsedAt,
      params.expiresAt,
      params.revokedAt,
      params.notes,
    );
  }

  public revoke(clock: Clock): AdminApiKey {
    if (this.revokedAt !== null) return this;
    return new AdminApiKey(
      this.id,
      this.name,
      this.keyHash,
      this.role,
      this.createdAt,
      this.createdBy,
      this.lastUsedAt,
      this.expiresAt,
      clock.now(),
      this.notes,
    );
  }

  public markUsed(clock: Clock): AdminApiKey {
    return new AdminApiKey(
      this.id,
      this.name,
      this.keyHash,
      this.role,
      this.createdAt,
      this.createdBy,
      clock.now(),
      this.expiresAt,
      this.revokedAt,
      this.notes,
    );
  }

  public isAliveAt(when: Date): boolean {
    if (this.revokedAt !== null) return false;
    if (this.expiresAt.getTime() <= when.getTime()) return false;
    return true;
  }
}

/**
 * Generate a fresh 32-byte base64url-encoded admin API key plaintext.
 * 256 bits of entropy; argon2id-hashed before storage.
 */
export function generateAdminApiKeyPlaintext(): string {
  return randomBytes(32).toString('base64url');
}
