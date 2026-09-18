import { DomainEvent } from './domain-event';

/**
 * Domain event — write side (publish).
 *
 * Used by use-cases that produce events. The application layer calls
 * `publish()` AFTER the transaction commits (see the documented sharp
 * edge on `RegisterUserUseCase` for why).
 */
export interface DomainEventPublisher {
  publish(event: DomainEvent): Promise<void>;
  publishAll(events: ReadonlyArray<DomainEvent>): Promise<void>;
}

/**
 * Domain event — read side (subscribe).
 *
 * Used by event handlers. Subscribers register at boot time (typically
 * via `OnModuleInit`) and the bus dispatches events to them by `eventName`.
 *
 * Subscribers that throw MUST NOT prevent other subscribers from running.
 * Errors from subscribers are logged, not re-thrown, so that one buggy
 * consumer cannot bring down the request path.
 */
export interface DomainEventSubscriber {
  subscribe(
    eventName: string,
    handler: (event: DomainEvent) => Promise<void> | void,
  ): { unsubscribe(): void };
}

/**
 * Combined bus for now — V1 ships one in-memory implementation that
 * satisfies both interfaces. When we move to Redis Streams / Kafka we
 * split into publisher + subscriber adapters with different lifetimes.
 */
export interface EventBus extends DomainEventPublisher, DomainEventSubscriber {}

/** NestJS DI token. */
export const EVENT_BUS = Symbol('EventBus');
