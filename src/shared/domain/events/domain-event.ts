/**
 * Domain event base.
 *
 * Domain events are emitted by aggregates when their state changes in a way
 * that other bounded contexts might care about. They are NOT used for
 * in-process signalling (that's what method calls are for); they ARE used to
 * decouple contexts that legitimately need to react to each other without
 * direct dependencies.
 *
 * Concrete events live in `<bounded-context>/domain/events/<event-name>.ts`
 * and extend this base. Each event:
 *
 *   * Carries the `occurredAt` timestamp from the clock port (never `new Date()`
 *     inline — that's a hidden dependency on the system clock).
 *   * Carries an `eventId` (UUID) so consumers can dedupe.
 *   * Is immutable — once raised, it travels through the bus verbatim.
 */
export interface DomainEvent {
  /** Stable identifier for deduplication on the consumer side. */
  readonly eventId: string;

  /** Aggregate root type that emitted the event (e.g. 'User'). */
  readonly aggregateType: string;

  /** Aggregate root ID that emitted the event. */
  readonly aggregateId: string;

  /** When the event occurred, in UTC. */
  readonly occurredAt: Date;

  /** Stable event name, used by the bus to route. */
  readonly eventName: string;
}
