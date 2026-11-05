import { Tx } from '../../../shared/domain';
import { Service } from '../aggregates/service';
import { ServiceSlug } from '../value-objects/service-slug';

export abstract class ServiceRepository {
  public abstract findBySlug(
    tx: Tx,
    slug: ServiceSlug,
  ): Promise<Service | null>;

  public abstract findById(tx: Tx, id: string): Promise<Service | null>;

  public abstract save(tx: Tx, service: Service): Promise<Service>;

  public abstract list(tx: Tx): Promise<ReadonlyArray<Service>>;
}

export const SERVICE_REPOSITORY = Symbol('ServiceRepository');
