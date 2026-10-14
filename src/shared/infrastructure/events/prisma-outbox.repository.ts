import { Inject, Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { Tx } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import { Outbox } from '../../../shared/domain/events/outbox.port';
import { PrismaService } from '../../../prisma/prisma.service';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for the outbox. Writes each event as a row in
 * `outbox_events` inside the caller's transaction.
 *
 * V1.5: see `outbox.port.ts` for the pattern. The relay polls this
 * table; subscribers consume from the in-process EventBus.
 */
@Injectable()
export class PrismaOutbox extends Outbox {
  public constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
  ) {
    super();
  }

  public async append(tx: Tx, event: DomainEvent): Promise<void> {
    const client = tx as PrismaTx;
    await client.outboxEvent.create({
      data: {
        id: this.eventIdFor(event),
        eventName: event.eventName,
        aggregateType: event.aggregateType,
        aggregateId: event.aggregateId,
        payload: this.serialize(event) as Prisma.InputJsonValue,
      },
    });
  }

  public async appendAll(
    tx: Tx,
    events: ReadonlyArray<DomainEvent>,
  ): Promise<void> {
    if (events.length === 0) return;
    const client = tx as PrismaTx;
    await client.outboxEvent.createMany({
      data: events.map((event) => ({
        id: this.eventIdFor(event),
        eventName: event.eventName,
        aggregateType: event.aggregateType,
        aggregateId: event.aggregateId,
        payload: this.serialize(event) as Prisma.InputJsonValue,
      })),
    });
  }

  /**
   * Reuse the event's own id for the outbox row — one-to-one mapping.
   * Makes idempotent re-publish (relay running twice) trivial: the
   * relay's `update` only flips `processedAt`, so the same id is
   * safe to re-publish.
   */
  private eventIdFor(event: DomainEvent): string {
    return event.eventId;
  }

  /**
   * Serialize the event into a JSON-safe payload. We persist the
   * public fields of the event (everything except framework-
   * internal state) so the relay can rehydrate an instance of the
   * same class.
   *
   * VOs (e.g. `UserId`, `SessionId`) are flattened: their `.value`
   * string is written at the field name. So `event.userId` (a
   * `UserId` VO with `.value === 'abc'`) becomes
   * `payload.userId === 'abc'`, NOT `payload.userId === { value: 'abc' }`.
   * The rehydrate step then re-wraps with `UserId.rehydrate(rawString)`.
   */
  private serialize(event: DomainEvent): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      __class: event.constructor.name,
      eventId: event.eventId,
      eventName: event.eventName,
      aggregateType: event.aggregateType,
      aggregateId: event.aggregateId,
      occurredAt: event.occurredAt.toISOString(),
    };
    for (const [k, v] of Object.entries(event)) {
      if (k in payload) continue;
      if (typeof v === 'function') continue;
      // Flatten VOs: write the underlying primitive at the field
      // name. Anything with a `value` field that is a string is
      // assumed to be a VO. (This is the same shape every
      // `EntityId` subclass in this codebase uses.)
      if (
        v !== null &&
        typeof v === 'object' &&
        'value' in v &&
        typeof (v as { value: unknown }).value === 'string'
      ) {
        payload[k] = (v as { value: string }).value;
        continue;
      }
      // Dates → ISO strings (Prisma already does this for its own
      // Date fields, but custom Date fields need help).
      if (v instanceof Date) {
        payload[k] = v.toISOString();
        continue;
      }
      payload[k] = v;
    }
    return payload;
  }
}
