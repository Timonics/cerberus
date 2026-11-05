import { Clock, DomainError } from '../../../shared/domain';
import { ServiceSlug } from '../value-objects/service-slug';

export type ServiceStatusValue = 'ACTIVE' | 'INACTIVE';

/**
 * Catalog service aggregate root.
 *
 * One row per product/service this deployment offers (the operator's
 * internal services). Provisioned and deactivated via the admin
 * surface; organizations get access through `ServiceEntitlement`.
 *
 * Invariants:
 *
 *   * `slug` is validated at construction and immutable — it appears in
 *     issued JWTs (`service:<slug>` scope); renaming the identifier
 *     would invalidate every token mid-flight.
 *
 *   * `name` is non-empty and ≤ 120 characters.
 *
 *   * INACTIVE is a soft-off: entitlements remain, but token issuance
 *     stops minting scopes for this service.
 */
export class Service {
  private constructor(
    public readonly id: string,
    public readonly slug: ServiceSlug,
    public readonly name: string,
    public readonly description: string | null,
    public readonly status: ServiceStatusValue,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
  ) {}

  public static create(params: {
    clock: Clock;
    id: string;
    slug: ServiceSlug;
    name: string;
    description: string | null;
  }): Service {
    Service.assertName(params.name);
    const now = params.clock.now();
    return new Service(
      params.id,
      params.slug,
      params.name,
      params.description,
      'ACTIVE',
      now,
      now,
    );
  }

  public static fromPersistence(params: {
    id: string;
    slug: ServiceSlug;
    name: string;
    description: string | null;
    status: ServiceStatusValue;
    createdAt: Date;
    updatedAt: Date;
  }): Service {
    return new Service(
      params.id,
      params.slug,
      params.name,
      params.description,
      params.status,
      params.createdAt,
      params.updatedAt,
    );
  }

  public rename(clock: Clock, name: string): Service {
    Service.assertName(name);
    return this.copy({ clock, name });
  }

  public setDescription(clock: Clock, description: string | null): Service {
    return this.copy({ clock, description });
  }

  public deactivate(clock: Clock): Service {
    return this.copy({ clock, status: 'INACTIVE' });
  }

  public activate(clock: Clock): Service {
    return this.copy({ clock, status: 'ACTIVE' });
  }

  public isActive(): boolean {
    return this.status === 'ACTIVE';
  }

  private copy(overrides: {
    clock: Clock;
    name?: string;
    description?: string | null;
    status?: ServiceStatusValue;
  }): Service {
    return new Service(
      this.id,
      this.slug,
      overrides.name ?? this.name,
      overrides.description !== undefined
        ? overrides.description
        : this.description,
      overrides.status ?? this.status,
      this.createdAt,
      overrides.clock.now(),
    );
  }

  private static assertName(name: string): void {
    if (typeof name !== 'string' || name.trim().length === 0) {
      throw new DomainError(
        'domain.invariant_violation',
        'Service name must be a non-empty string',
      );
    }
    if (name.length > 120) {
      throw new DomainError(
        'domain.invariant_violation',
        'Service name must be ≤ 120 characters',
        { length: name.length },
      );
    }
  }
}
