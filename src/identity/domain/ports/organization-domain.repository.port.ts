import { Tx } from '../../../shared/domain';

/**
 * Organization-domain lookup row.
 *
 * Lightweight value object — no aggregate here, just a (domain → orgId)
 * mapping that the registration flow reads on every signup. Returns a
 * `null` org id when no domain row is registered (the registration flow
 * then falls back to creating a personal org).
 */
export interface OrganizationDomainRow {
  readonly organizationId: string;
  readonly domain: string;
}

/**
 * OrganizationDomain repository port.
 *
 * Used by `RegisterUserUseCase` to look up the org from the user's email
 * domain. The repo deliberately has no `save`/`delete` — domain
 * registration is an admin operation that ships in the Administration
 * bounded context (V1.5).
 */
export abstract class OrganizationDomainRepository {
  public abstract findByDomain(
    tx: Tx,
    domain: string,
  ): Promise<OrganizationDomainRow | null>;
}

export const ORGANIZATION_DOMAIN_REPOSITORY = Symbol(
  'OrganizationDomainRepository',
);
