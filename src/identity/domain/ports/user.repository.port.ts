import { BaseRepository, Tx } from '../../../shared/domain';
import { User } from '../aggregates/user';
import { UserId } from '../value-objects/user-id';

/**
 * User repository port.
 *
 * Defined in the domain layer; the Prisma adapter in `infrastructure/`
 * implements it. The domain code only ever depends on this interface, so
 * the persistence choice is swappable.
 *
 * Note: this repository owns the `users` table only. The Organization,
 * Membership, and Credential aggregates each have their own repository
 * because they live in their own tables. Cross-aggregate operations
 * (e.g. RegisterUserUseCase writing all of them atomically) compose
 * multiple repositories inside a single transaction.
 */
export abstract class UserRepository extends BaseRepository<User, UserId> {
  /**
   * Find a user by their canonical email address.
   * Used by login flows and by registration to enforce uniqueness.
   */
  public abstract findByEmail(tx: Tx, email: string): Promise<User | null>;

  /**
   * Quick existence check. Cheaper than `findByEmail` when the caller
   * only needs to know whether a user with this email exists.
   */
  public abstract existsWithEmail(tx: Tx, email: string): Promise<boolean>;
}

/** Nest DI token for the UserRepository port. */
export const USER_REPOSITORY = Symbol('UserRepository');
