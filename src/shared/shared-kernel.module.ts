import { Global, Module } from '@nestjs/common';
import { SystemClock } from './infrastructure/clock/system-clock';
import { UuidIdGenerator } from './infrastructure/ids/uuid-id-generator';
import { InMemoryEventBus } from './infrastructure/events/in-memory-event-bus';
import { PrismaTransactionRunner } from './infrastructure/persistence/prisma-transaction-runner';
import { CLOCK, EVENT_BUS, ID_GENERATOR, TRANSACTION_RUNNER } from './domain';

/**
 * Shared kernel module.
 *
 * Marked `@Global()` so the Clock, IdGenerator, EventBus, and
 * TransactionRunner are available everywhere without re-importing the
 * module. Each port is bound to a concrete class — when injecting,
 * consumers reference the symbol so the type system enforces the port
 * contract, but Nest knows which concrete instance to wire.
 */
@Global()
@Module({
  providers: [
    SystemClock,
    InMemoryEventBus,
    PrismaTransactionRunner,
    UuidIdGenerator,
    { provide: CLOCK, useExisting: SystemClock },
    { provide: EVENT_BUS, useExisting: InMemoryEventBus },
    { provide: TRANSACTION_RUNNER, useExisting: PrismaTransactionRunner },
    { provide: ID_GENERATOR, useExisting: UuidIdGenerator },
  ],
  exports: [CLOCK, EVENT_BUS, ID_GENERATOR, TRANSACTION_RUNNER],
})
export class SharedKernelModule {}
