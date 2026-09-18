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
}

export const SESSION_REPOSITORY = Symbol('SessionRepository');
