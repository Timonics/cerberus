/**
 * Generic opaque-identifier value object.
 *
 * Every aggregate ID in this codebase is a UUID string. We could just use the
 * primitive type, but wrapping it gives us:
 *
 *   * Distinct types per aggregate (`UserId`, `OrgId`, `SessionId` ...),
 *     so the type system refuses to swap a `SessionId` for a `UserId` in
 *     signatures. This catches real bugs.
 *   * A consistent place for `rehydrate()` semantics — the database column
 *     is just a string, but loading it produces a strongly-typed ID.
 *   * Centralized validation (UUIDs are checked at construction time, never
 *     silently accepted).
 *
 * We define `EntityId` as a base class and let each bounded context define
 * its own branded subclass (`UserId extends EntityId<'UserId'>`) via the
 * nominal-typing trick of phantom string types.
 */
export abstract class EntityId<TBrand extends string> {
  public readonly value: string;
  /** Phantom type tag — narrows the type at compile time only. */
  protected readonly _brand!: TBrand;

  protected constructor(value: string) {
    this.value = value;
  }

  /** Compare two IDs by their string value. */
  public equals(other: EntityId<TBrand>): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }

  /** JSON-friendly representation for persistence boundaries. */
  public toJSON(): string {
    return this.value;
  }
}

/**
 * Validate that a string looks like a UUID (v1–v5 or v7 — Prisma uses v4
 * but we don't pin the version here so tests can use deterministic UUIDs).
 */
export function assertUuid(raw: string, label: string): void {
  if (typeof raw !== 'string' || !UUID_RE.test(raw)) {
    throw new Error(`${label} must be a valid UUID, got: ${String(raw)}`);
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Concrete ID types — one per aggregate. Keep these in the domain layer where
// the aggregate lives, NOT in shared/. The pattern shown here (extend with a
// private constructor + a static factory) lets the concrete ID enforce its
// own validation rules if it needs to.
// ---------------------------------------------------------------------------

/** A user aggregate ID. Defined in `src/identity/domain/value-objects/user-id.ts`. */
/** An organization aggregate ID. Defined in `src/identity/domain/value-objects/org-id.ts`. */
/** A session aggregate ID. Defined in `src/authentication/domain/value-objects/session-id.ts`. */
