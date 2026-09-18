import { BaseRepository, Tx } from '../../../shared/domain';
import { Membership } from '../aggregates/membership';
import { OrgId } from '../value-objects/org-id';
import { UserId } from '../value-objects/user-id';

/**
 * Membership repository port.
 *
 * Owns the `memberships` table. In V1 a user has exactly one membership,
 * so the most common access path is `findByUserId`. The
 * `findByOrganizationId` method supports admin queries ("list users in
 * this org").
 *
 * For V2 (multi-org) this repository will gain `findByUserAndOrg` to
 * scope a membership to a specific organization.
 */
export abstract class MembershipRepository extends BaseRepository<
  Membership,
  string
> {
  /** Find the membership a user holds. Returns null if user has no membership. */
  public abstract findByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<Membership | null>;

  /** List all memberships in an organization. Admin / reporting use case. */
  public abstract findByOrganizationId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<Membership>>;
}

export const MEMBERSHIP_REPOSITORY = Symbol('MembershipRepository');
