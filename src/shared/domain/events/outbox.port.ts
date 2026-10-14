import { Tx } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';

/**
 * V1.5 outbox port — persists domain events inside the originating
 * DB transaction so the relay can re-publish them across a process
 * restart. This is the "write half" of the transactional outbox
 * pattern: the relay (in `outbox-relay.ts`) is the "publish half".
 *
 * Callers MUST invoke `append` from within a `txRunner.run(async tx => …)`
 * block so the row commits atomically with the aggregate change. The
 * service-layer `TransactionalOutbox` wrapper enforces this.
 */
export abstract class Outbox {
  /**
   * Persist a single domain event into the outbox table. Must be
   * called inside a transaction.
   */
  public abstract append(tx: Tx, event: DomainEvent): Promise<void>;

  /**
   * Persist multiple domain events in one call. Same tx rules as
   * `append`.
   */
  public abstract appendAll(
    tx: Tx,
    events: ReadonlyArray<DomainEvent>,
  ): Promise<void>;
}

export const OUTBOX = Symbol('Outbox');
