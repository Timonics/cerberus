import { BaseRepository, Tx } from '../../../shared/domain';
import { Session } from '../aggregates/session';
import { SessionId } from '../value-objects/session-id';
import { UserId } from '../../../identity/domain/value-objects/user-id';

/**
 * Session repository port.
 *
 * The aggregate carries the refresh-token hash, but the repository
 * also needs to do fast lookups by hash (every refresh request is a
 * hash lookup). We expose `findByRefreshHash` as an extra method beyond
 * the base `findById`.
 *
 * `revokeAllInFamily` is invoked when reuse is detected: it sets
 * `revokedAt` on every non row in the family in a single SQL UPDATE.
 */
export abstract class SessionRepository extends BaseRepository<
  Session,
  SessionId
> {
  public abstract findByRefreshHash(
    tx: Tx,
    refreshHash: string,
  ): Promise<Session | null>;

  /**
   * 2026-10-19 audit fix H-7: look up a session whose
   * `previousRefreshHashes` array contains the given (already-rotated)
   * hash. This is the reuse-detection lookup: a presented hash that is
   * no longer the current `refreshHash` but appears in the rotation
   * history is either a legitimate retry inside the grace window or a
   * stolen token — the caller decides using `lastRotatedAt`.
   */
  public abstract findByPreviousHash(
    tx: Tx,
    refreshHash: string,
  ): Promise<Session | null>;

  public abstract findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<ReadonlyArray<Session>>;

  /**
   * Revoke every non row in `familyId`. Returns the number of rows
   * affected (useful for logging when reuse is detected).
   */
  public abstract revokeAllInFamily(
    tx: Tx,
    familyId: string,
    reason: 'PASSWORD_CHANGED' | 'FAMILY_COMPROMISED' | 'ADMIN_REVOKED',
  ): Promise<number>;

  /**
   * Revoke every active session belonging to `userId`. Used by the
   * PasswordChanged handler.
   */
  public abstract revokeAllForUser(
    tx: Tx,
    userId: UserId,
    reason: 'PASSWORD_CHANGED' | 'ADMIN_REVOKED',
  ): Promise<number>;

  /**
   * V1.5 (audit C-4): flip mfaVerified to true on a specific
   * session. Used by VerifySecondFactorUseCase. Returns the updated
   * session so the caller can include session metadata in the audit.
   */
  public abstract markMfaVerified(
    tx: Tx,
    sessionId: SessionId,
  ): Promise<Session | null>;

  /**
   * V1.5 (audit H-1): atomic compare-and-swap rotation. Refuses
   * to rotate unless the current row's `refreshHash` equals
   * `currentHash`. Returns true if the rotation succeeded, false
   * if another concurrent rotation already wrote (in which case the
   * caller re-reads the row and classifies the attempt: hash now in
   * `previousRefreshHashes` → grace-window idempotent retry; otherwise
   * → family compromise).
   *
   * This is the only safe way to rotate refresh tokens under Prisma's
   * default READ COMMITTED isolation — a non-atomic read-then-write
   * allows two concurrent rotations to both succeed.
   */
  public abstract rotateRefreshTokenAtomic(
    tx: Tx,
    currentHash: string,
    next: {
      refreshHash: string;
      expiresAt: Date;
      lastUsedAt: Date;
      /** 2026-10-19 audit fix H-7: rotation timestamp for the grace window. */
      lastRotatedAt: Date;
      previousRefreshHashes: ReadonlyArray<string>;
    },
  ): Promise<boolean>;
}

export const SESSION_REPOSITORY = Symbol('SessionRepository');
