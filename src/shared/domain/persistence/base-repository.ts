import { Tx } from './tx';

/**
 * Base repository contract.
 *
 * Every bounded context defines its own concrete repository class
 * (e.g. `PrismaUserRepository extends BaseRepository<User, UserId>`) that
 * inherits this shape. The base class itself is abstract — it can't be
 * instantiated. It exists to:
 *
 *   1. Force every repo to implement the same `findById / save / delete`
 *      trio so consumers can compose them polymorphically if needed.
 *
 *   2. Provide a single place to add new repo-wide operations later
 *      (e.g. `findMany` with paging, soft-delete recovery, etc.) without
 *      editing 12 implementations.
 *
 *   3. Anchor the `Tx` parameter pattern — concrete repos cannot forget to
 *      thread `tx` through because the base method signatures are
 *      authoritative.
 *
 * Implementation note: subclasses receive a `PrismaClient` (or its
 * transactional variant) at construction time. Concrete repos know how to
 * narrow `Tx` back to `Prisma.TransactionClient` for their queries.
 */
export abstract class BaseRepository<TAggregate, TId> {
  /**
   * Load an aggregate by ID. Returns `null` when not found — never throw
   * for a missing row. Use-cases translate `null` into a domain error.
   */
  public abstract findById(tx: Tx, id: TId): Promise<TAggregate | null>;

  /**
   * Persist the aggregate. The repo decides whether to INSERT or UPDATE
   * (typically by checking whether the aggregate's ID is new).
   *
   * Returns the persisted aggregate (may be the same instance, or a
   * rehydrated copy from the DB if the repo normalizes fields on write).
   */
  public abstract save(tx: Tx, aggregate: TAggregate): Promise<TAggregate>;

  /**
   * Hard-delete the aggregate. For soft-delete semantics, the aggregate
   * itself exposes a `markDeleted()` domain method and the repo simply
   * saves the updated state — DELETE here is reserved for cases where
   * the user-data-deletion right (GDPR Art. 17) applies.
   */
  public abstract delete(tx: Tx, id: TId): Promise<void>;
}
