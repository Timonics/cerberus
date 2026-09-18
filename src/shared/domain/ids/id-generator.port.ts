/**
 * Identifier minting port.
 *
 * Used by aggregate factories and use-cases to mint new opaque IDs.
 *
 * The default implementation (in `infrastructure/`) uses
 * `crypto.randomUUID()` so the IDs match the database schema's
 * `@default(uuid())` columns and pass `EntityId.assertUuid` validation.
 *
 * Tests inject a deterministic ID generator (e.g. a counter) so golden
 * snapshots stay stable.
 */
export interface IdGenerator {
  /** Generate a new opaque identifier (RFC 4122 v4 UUID by default). */
  generate(): string;
}

export const ID_GENERATOR = Symbol('IdGenerator');
