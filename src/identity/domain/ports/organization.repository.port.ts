import { BaseRepository, Tx } from '../../../shared/domain';
import { Organization } from '../aggregates/organization';
import { OrgId } from '../value-objects/org-id';
import { OrgSlug } from '../value-objects/org-slug';

/**
 * Organization repository port.
 *
 * Owns the `organizations` table. Used by RegisterUserUseCase to create
 * the org in the same transaction as the user + credential.
 *
 * The slug uniqueness check happens at the DB level (UNIQUE constraint);
 * the repository translates a P2002 Prisma error into a domain error
 * (the use-case never sees Prisma).
 */
export abstract class OrganizationRepository extends BaseRepository<
  Organization,
  OrgId
> {
  public abstract findBySlug(
    tx: Tx,
    slug: OrgSlug,
  ): Promise<Organization | null>;

  public abstract existsWithSlug(tx: Tx, slug: OrgSlug): Promise<boolean>;
}

export const ORGANIZATION_REPOSITORY = Symbol('OrganizationRepository');
