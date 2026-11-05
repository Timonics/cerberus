import { Tx } from '../../../shared/domain';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import { ServiceEntitlement } from '../aggregates/service-entitlement';
import { Service } from '../aggregates/service';

/**
 * Entitlement paired with its service — the read model token issuance
 * and admin listings consume. Repositories map the join at the
 * persistence boundary so the domain never sees Prisma row shapes.
 */
export interface EntitlementWithService {
  readonly entitlement: ServiceEntitlement;
  readonly service: Service;
}

export abstract class ServiceEntitlementRepository {
  public abstract findByOrgAndService(
    tx: Tx,
    organizationId: OrgId,
    serviceId: string,
  ): Promise<ServiceEntitlement | null>;

  /**
   * ACTIVE entitlements of an org with their service rows joined —
   * what token issuance needs to mint `service:<slug>` scopes.
   * INACTIVE services are excluded (a soft-off catalog entry must not
   * mint scopes even while the entitlement row stays ACTIVE).
   */
  public abstract findActiveWithServiceByOrgId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<EntitlementWithService>>;

  /**
   * All entitlements of an org (any status) with service rows joined —
   * the admin "what does this org have" listing.
   */
  public abstract findWithServiceByOrgId(
    tx: Tx,
    organizationId: OrgId,
  ): Promise<ReadonlyArray<EntitlementWithService>>;

  public abstract save(
    tx: Tx,
    entitlement: ServiceEntitlement,
  ): Promise<ServiceEntitlement>;
}

export const SERVICE_ENTITLEMENT_REPOSITORY = Symbol(
  'ServiceEntitlementRepository',
);
