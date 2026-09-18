import { Inject, Injectable, Logger } from '@nestjs/common';
import { nanoid } from 'nanoid';
import { Clock, CLOCK } from '../../domain/clock/clock.port';
import { DomainEvent } from '../../domain/events/domain-event';
import { EventBus, EVENT_BUS } from '../../domain/events/event-bus.port';
import { ID_GENERATOR, IdGenerator } from '../../domain/ids/id-generator.port';

/**
 * Subscription token returned by `EventBus.subscribe()`.
 * Used to unsubscribe later (e.g. on module teardown in tests).
 */
export interface Subscription {
  unsubscribe(): void;
}

/**
 * Per-event subscription table: each subscriber listens to a single event
 * type. We do not support wildcards — explicit subscriptions are easier to
 * audit and easier to mock.
 */
type Handler = (event: DomainEvent) => Promise<void> | void;

interface Subscriber {
  readonly eventName: string;
  readonly handler: Handler;
}

/**
 * In-process event bus.
 *
 * V1 ships with this; the production-grade replacement (Redis Streams or
 * Kafka) is a V2 concern. Until then, all cross-context communication
 * happens via direct in-memory dispatch, which keeps the deployment story
 * single-binary.
 *
 * Failure semantics:
 *
 *   * Subscribers run in registration order.
 *   * A subscriber that throws logs the error and the bus continues to the
 *     next subscriber. The original publisher is NOT failed.
 *   * This is intentional — auth flows must not be coupled to non-critical
 *     side effects (e.g. analytics, audit-log shipping). Critical
 *     subscriptions (e.g. audit-log persistence) should be modelled as
 *     in-process subscribers that the publisher can wait on via
 *     `publishAndWait()`. For V1 we use plain `publish()` and accept that
 *     audit logging is best-effort, but the audit-log writer also runs as
 *     an in-band transaction step in critical paths.
 */
@Injectable()
export class InMemoryEventBus implements EventBus {
  private readonly logger = new Logger(InMemoryEventBus.name);
  private readonly subscribers: Subscriber[] = [];

  public constructor(
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
  ) {}

  /**
   * Register a handler for a specific event name. Returns a Subscription the
   * caller can use to unregister.
   */
  public subscribe(eventName: string, handler: Handler): Subscription {
    const subscriber: Subscriber = { eventName, handler };
    this.subscribers.push(subscriber);
    return {
      unsubscribe: () => {
        const idx = this.subscribers.indexOf(subscriber);
        if (idx >= 0) {
          this.subscribers.splice(idx, 1);
        }
      },
    };
  }

  /**
   * Publish a single event. Subscribers are run in registration order; their
   * errors are logged but never re-thrown.
   */
  public async publish(event: DomainEvent): Promise<void> {
    const matching = this.subscribers.filter(
      (s) => s.eventName === event.eventName,
    );
    for (const subscriber of matching) {
      try {
        await subscriber.handler(event);
      } catch (err) {
        this.logger.error(
          `Event subscriber for "${event.eventName}" threw: ${String(err)}`,
        );
      }
    }
  }

  /**
   * Publish a batch of events in order. Each event is dispatched to its
   * matching handlers sequentially. If any handler throws, we log and
   * continue.
   */
  public async publishAll(events: ReadonlyArray<DomainEvent>): Promise<void> {
    for (const event of events) {
      await this.publish(event);
    }
  }

  /**
   * Mint a new event ID. Aggregate factories use this so the ID comes from
   * the same place as everything else (no `crypto.randomUUID()` sprinkled
   * throughout the codebase).
   */
  public nextEventId(): string {
    return this.idGenerator.generate();
  }

  /** Helper for event factory functions to stamp the occurredAt timestamp. */
  public now(): Date {
    return this.clock.now();
  }

  /** Helper for ID generation, exposed for aggregate factories. */
  public newId(): string {
    return this.idGenerator.generate();
  }

  /**
   * Convenience for use-cases that want to write a domain event without
   * knowing how the bus constructs one. Most aggregates will call this
   * directly from inside the aggregate factory.
   */
  public static readonly EventBusSymbol = EVENT_BUS;
}

/** Re-export DI tokens so consumers don't have to know the inner path. */
export { CLOCK, EVENT_BUS, ID_GENERATOR };
// Suppress unused-import warning for `nanoid` (kept for future use by
// callers wanting a quick ID without injecting the IdGenerator port).
void nanoid;
