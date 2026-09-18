import {
  EntityId,
  assertUuid,
} from '../../../shared/domain/value-objects/entity-id';

/**
 * User aggregate ID.
 *
 * Concrete subclass of the shared-kernel `EntityId<'User'>` to give it a
 * distinct type. Functions that ask for `UserId` cannot be called with a
 * `SessionId` or `OrgId` — the type system refuses.
 *
 * Constructed only via the static factory `create()` (for new IDs) or
 * `rehydrate()` (when loading from the database). The constructor is
 * `protected` so subclasses can pass through, but external code cannot
 * bypass validation.
 */
export class UserId extends EntityId<'User'> {
  private static readonly BRAND = 'User' as const;

  /** Create a brand-new user ID from a fresh UUID string. */
  public static create(raw: string): UserId {
    assertUuid(raw, 'UserId');
    return new UserId(raw);
  }

  /**
   * Rehydrate from a previously-stored string (e.g. loaded from Postgres).
   * Performs the same validation as `create()` so we never end up with a
   * "UserId" holding garbage.
   */
  public static rehydrate(raw: string): UserId {
    assertUuid(raw, 'UserId');
    return new UserId(raw);
  }

  protected constructor(value: string) {
    super(value);
  }

  /** Phantom tag, used internally by the type system. */
  protected get brand(): 'User' {
    return UserId.BRAND;
  }
}
