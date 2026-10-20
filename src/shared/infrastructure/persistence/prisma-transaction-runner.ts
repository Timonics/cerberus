import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { TransactionRunner } from '../../domain/persistence/transaction-runner.port';
import { Tx } from '../../domain/persistence/tx';

/**
 * Default TransactionRunner backed by Prisma.
 *
 * Wraps Prisma's `$transaction` interactive API. The `tx` argument passed to
 * the callback is a `Prisma.TransactionClient` — Prisma's own type narrows
 * to it implicitly. We type it as `Tx` (i.e. `unknown`) here to keep the
 * domain layer Prisma-free; consumers narrow back to the Prisma client when
 * they need to issue queries.
 *
 * Isolation level: Prisma defaults to `READ COMMITTED`, which is what we
 * want for an auth service — we don't need the stronger guarantees of
 * `SERIALIZABLE`, and the perf cost would be significant under load.
 */
@Injectable()
export class PrismaTransactionRunner implements TransactionRunner {
  public constructor(private readonly prisma: PrismaService) {}

  public async run<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    // 20s interactive-transaction ceiling (Prisma default is 5s): argon2id
    // verification and lock contention on busy hosts can stall a tx past
    // the default, surfacing raw P2028s to callers. 20s keeps the
    // still-alive safety net without the false-positive timeouts.
    return this.prisma.$transaction(async (tx) => work(tx), {
      timeout: 20_000,
    });
  }
}
