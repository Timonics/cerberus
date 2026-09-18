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
    // Prisma's $transaction accepts a callback returning a Promise. Inside,
    // the `tx` parameter is the transactional client. We hand it to the
    // callback as `Tx` (opaque); concrete repositories narrow it via
    // `tx as Prisma.TransactionClient` at the boundary.
    return this.prisma.$transaction(async (tx) => work(tx));
  }
}
