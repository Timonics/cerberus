import { Clock, DomainError } from '../../../shared/domain';
import { OrgId } from '../../../identity/domain/value-objects/org-id';

export type EntitlementStatusValue = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';

/**
 * Service entitlement aggregate.
 *
 * Records that an Organization has access to a catalog Service. One row
 * per (org, service) pair — revoking and re-granting reuses the same
 * row so grant history stays on a single aggregate.
 *
 * Status machine:
 *
 *   ACTIVE ⇄ SUSPENDED  (reversible pause, e.g. billing hold)
 *   ACTIVE → REVOKED    (terminal; re-grant = reactivate)
 *   SUSPENDED → REVOKED
 *
 * Invariants:
 *
 *   * `revoke()` / `suspend()` are idempotent — calling them in the
 *     same status returns `this` rather than shifting timestamps.
 *
 *   * Only ACTIVE entitlements mint `service:<slug>` scopes.
 */
export class ServiceEntitlement {
  private constructor(
    public readonly id: string,
    public readonly organizationId: OrgId,
    public readonly serviceId: string,
    public readonly status: EntitlementStatusValue,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
  ) {}

  public static grant(params: {
    clock: Clock;
    id: string;
    organizationId: OrgId;
    serviceId: string;
  }): ServiceEntitlement {
    const now = params.clock.now();
    return new ServiceEntitlement(
      params.id,
      params.organizationId,
      params.serviceId,
      'ACTIVE',
      now,
      now,
    );
  }

  public static fromPersistence(params: {
    id: string;
    organizationId: OrgId;
    serviceId: string;
    status: EntitlementStatusValue;
    createdAt: Date;
    updatedAt: Date;
  }): ServiceEntitlement {
    return new ServiceEntitlement(
      params.id,
      params.organizationId,
      params.serviceId,
      params.status,
      params.createdAt,
      params.updatedAt,
    );
  }

  public suspend(clock: Clock): ServiceEntitlement {
    if (this.status === 'SUSPENDED') return this;
    if (this.status === 'REVOKED') {
      throw new DomainError(
        'services.entitlement.revoked',
        'A revoked entitlement must be re-granted, not suspended',
        { entitlementId: this.id },
      );
    }
    return this.copy({ clock, status: 'SUSPENDED' });
  }

  public reactivate(clock: Clock): ServiceEntitlement {
    if (this.status === 'ACTIVE') return this;
    return this.copy({ clock, status: 'ACTIVE' });
  }

  public revoke(clock: Clock): ServiceEntitlement {
    if (this.status === 'REVOKED') return this;
    return this.copy({ clock, status: 'REVOKED' });
  }

  public isActive(): boolean {
    return this.status === 'ACTIVE';
  }

  private copy(overrides: {
    clock: Clock;
    status: EntitlementStatusValue;
  }): ServiceEntitlement {
    return new ServiceEntitlement(
      this.id,
      this.organizationId,
      this.serviceId,
      overrides.status,
      this.createdAt,
      overrides.clock.now(),
    );
  }
}
