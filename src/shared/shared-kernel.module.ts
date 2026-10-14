import { Global, Module } from '@nestjs/common';
import { SystemClock } from './infrastructure/clock/system-clock';
import { UuidIdGenerator } from './infrastructure/ids/uuid-id-generator';
import { InMemoryEventBus } from './infrastructure/events/in-memory-event-bus';
import { PrismaOutbox } from './infrastructure/events/prisma-outbox.repository';
import { OutboxRelay } from './infrastructure/events/outbox-relay';
import { PrismaTransactionRunner } from './infrastructure/persistence/prisma-transaction-runner';
import {
  CLOCK,
  EVENT_BUS,
  ID_GENERATOR,
  OUTBOX,
  TRANSACTION_RUNNER,
} from './domain';

/**
 * Shared kernel module.
 *
 * Marked `@Global()` so the Clock, IdGenerator, EventBus, and
 * TransactionRunner are available everywhere without re-importing the
 * module. Each port is bound to a concrete class — when injecting,
 * consumers reference the symbol so the type system enforces the port
 * contract, but Nest knows which concrete instance to wire.
 *
 * V1.5: also exposes the Outbox port + OutboxRelay so every bounded
 * context can append events to the outbox from inside its
 * transactions, and the relay re-publishes them through the
 * EventBus (consumed by MailSenderDispatcher, the audit-log
 * handler, etc.) on every poll tick.
 */
@Global()
@Module({
  providers: [
    SystemClock,
    InMemoryEventBus,
    PrismaTransactionRunner,
    UuidIdGenerator,
    PrismaOutbox,
    OutboxRelay,
    { provide: CLOCK, useExisting: SystemClock },
    { provide: EVENT_BUS, useExisting: InMemoryEventBus },
    { provide: TRANSACTION_RUNNER, useExisting: PrismaTransactionRunner },
    { provide: ID_GENERATOR, useExisting: UuidIdGenerator },
    { provide: OUTBOX, useExisting: PrismaOutbox },
  ],
  exports: [CLOCK, EVENT_BUS, ID_GENERATOR, OUTBOX, TRANSACTION_RUNNER],
})
export class SharedKernelModule {}
