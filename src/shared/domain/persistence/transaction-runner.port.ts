/**
 * Transaction runner port.
 *
 * Defined in the domain layer so use-cases can call
 * `this.txRunner.run(async (tx) => ...)` without importing any concrete
 * database driver.
 *
 * The default adapter in `shared/infrastructure/` wraps Prisma's
 * `$transaction` interactive API. Any implementation MUST guarantee:
 *
 *   * The `work` callback runs inside a single transactional unit.
 *   * If `work` throws, ALL changes are rolled back.
 *   * If `work` returns, ALL changes are committed atomically.
 *   * The `tx` argument passed to `work` is the same client that all
 *     subsequent repository calls must use for this unit of work.
 */
import { Tx } from './tx';

export interface TransactionRunner {
  run<T>(work: (tx: Tx) => Promise<T>): Promise<T>;
}

export const TRANSACTION_RUNNER = Symbol('TransactionRunner');
