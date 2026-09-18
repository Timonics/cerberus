import { Clock } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { OrgId } from '../value-objects/org-id';
import { Role } from '../value-objects/role';
import { UserId } from '../value-objects/user-id';

/**
 * Membership aggregate root.
 *
 * The join between a User and an Organization, carrying the role the user
 * holds inside that org. In V1 every user has exactly one membership;
 * V2 may allow multiple (user can belong to several orgs).
 *
 * The Membership aggregate is simpler than User — its invariants are
 * minimal:
 *
 *   * A user must have exactly one membership per organization
 * (enforced by the DB UNIQUE constraint on (userId, organizationId)).
 *
 *   * The role is one of OWNER / ADMIN / MEMBER.
 *
 *   * The membership is created with role = OWNER when the user is the
 *     first user of a new organization (V1 always). V2 may grant
 *     MEMBER for invitee users.
 */
export class Membership {
  private constructor(
    public readonly id: string,
    public readonly userId: UserId,
    public readonly organizationId: OrgId,
    public readonly role: Role,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  public static create(params: {
    id: string;
    userId: UserId;
    organizationId: OrgId;
    role: Role;
    clock: Clock;
  }): Membership {
    const now = params.clock.now();
    return new Membership(
      params.id,
      params.userId,
      params.organizationId,
      params.role,
      now,
      now,
      [],
    );
  }

  public static fromPersistence(params: {
    id: string;
    userId: UserId;
    organizationId: OrgId;
    role: Role;
    createdAt: Date;
    updatedAt: Date;
  }): Membership {
    return new Membership(
      params.id,
      params.userId,
      params.organizationId,
      params.role,
      params.createdAt,
      params.updatedAt,
      [],
    );
  }

  /** Promote or demote the user within the org. */
  public changeRole(role: Role, clock: Clock): Membership {
    if (this.role.equals(role)) {
      return this;
    }
    const now = clock.now();
    return new Membership(
      this.id,
      this.userId,
      this.organizationId,
      role,
      this.createdAt,
      now,
      this.pendingEvents,
    );
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}
