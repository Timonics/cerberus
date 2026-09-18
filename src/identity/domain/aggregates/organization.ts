import { Clock, DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { OrgId } from '../value-objects/org-id';
import { OrgSlug } from '../value-objects/org-slug';

/**
 * Organization aggregate root.
 *
 * The tenant root for multi-tenant isolation. Every User belongs to one
 * Organization, and roles / JWTs / audit entries are scoped to an
 * Organization. In V1 every user creates exactly one Organization at
 * registration time; V2 may introduce multi-org membership.
 *
 * Invariants:
 *
 *   * `slug` is unique across the system (enforced by DB UNIQUE
 *     constraint, validated at construction).
 *
 *   * `name` is non-empty and ≤ 120 characters.
 *
 *   * `slug` is immutable after creation. Changing the URL-safe identifier
 *     would break any cached URL the org owns. The display name CAN be
 *     changed.
 */
export class Organization {
  private constructor(
    public readonly id: OrgId,
    public readonly slug: OrgSlug,
    public readonly name: string,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  // -------------------------------------------------------------------------
  // Factory: new organization
  // -------------------------------------------------------------------------

  public static create(params: {
    clock: Clock;
    id: OrgId;
    slug: OrgSlug;
    name: string;
  }): Organization {
    Organization.assertName(params.name);

    const now = params.clock.now();
    return new Organization(
      params.id,
      params.slug,
      params.name,
      now,
      now,
      [], // registration does not emit an event here — the Organization's
      // // own lifecycle events (rename, delete, etc.) come later. The
      // // user's `UserRegistered` event already records the org ID.
    );
  }

  // -------------------------------------------------------------------------
  // Factory: rehydrate from persistence
  // -------------------------------------------------------------------------

  public static fromPersistence(params: {
    id: OrgId;
    slug: OrgSlug;
    name: string;
    createdAt: Date;
    updatedAt: Date;
  }): Organization {
    return new Organization(
      params.id,
      params.slug,
      params.name,
      params.createdAt,
      params.updatedAt,
      [],
    );
  }

  // -------------------------------------------------------------------------
  // Domain methods
  // -------------------------------------------------------------------------

  /** Rename the organization. Validates the new name's length. */
  public rename(clock: Clock, name: string): Organization {
    Organization.assertName(name);
    const now = clock.now();
    return new Organization(
      this.id,
      this.slug,
      name,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }

  private static assertName(name: string): void {
    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new DomainError(
        'domain.invariant_violation',
        'Organization name must be a non-empty string',
      );
    }
    if (name.length > 120) {
      throw new DomainError(
        'domain.invariant_violation',
        'Organization name must be at most 120 characters',
        { length: name.length },
      );
    }
  }
}
