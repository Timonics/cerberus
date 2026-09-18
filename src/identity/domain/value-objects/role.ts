import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Role value object.
 *
 * A Role is one of three fixed values per the V1 product scope:
 *
 *   * `OWNER` — the user who created the organization. Has all permissions,
 *     including destructive ones like deleting the org.
 *   * `ADMIN` — can manage users in the org but cannot delete it.
 *   * `MEMBER` — default role on registration.
 *
 * Roles are scoped to a single Organization in V1 (one user → one role per
 * org). The V2 upgrade to multi-org-per-user would require a `MembershipId`
 * to be passed alongside the Role everywhere it's used; we don't add that
 * yet because we don't need it.
 */
export type RoleValue = 'OWNER' | 'ADMIN' | 'MEMBER';

export class Role {
  public readonly value: RoleValue;

  private constructor(value: RoleValue) {
    this.value = value;
  }

  /** Construct a Role from a known-good enum value. */
  public static create(value: RoleValue): Role {
    if (!Role.isValidValue(value)) {
      throw new DomainError(
        'authorization.role.not_found',
        `Unknown role: ${String(value)}`,
      );
    }
    return new Role(value);
  }

  /**
   * Rehydrate from a raw database string. Rejects unknown values rather
   * than silently coercing to `MEMBER`, so a schema migration that
   * introduces a new role value is caught loudly at startup, not silently.
   */
  public static rehydrate(value: string): Role {
    if (!Role.isValidValue(value)) {
      throw new DomainError(
        'authorization.role.not_found',
        `Unknown role in database: ${value}`,
      );
    }
    return new Role(value);
  }

  public equals(other: Role): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }

  /**
   * Coarse-grained permission check used by the authorization context.
   *
   * The hierarchy is: OWNER > ADMIN > MEMBER. If you need fine-grained
   * permissions, use scopes on the JWT instead of role comparison.
   *
   * @returns true if `this` role's level is >= `other`'s.
   */
  public isAtLeast(other: Role): boolean {
    const rank: Record<RoleValue, number> = {
      OWNER: 3,
      ADMIN: 2,
      MEMBER: 1,
    };
    return rank[this.value] >= rank[other.value];
  }

  private static isValidValue(value: unknown): value is RoleValue {
    return value === 'OWNER' || value === 'ADMIN' || value === 'MEMBER';
  }
}
