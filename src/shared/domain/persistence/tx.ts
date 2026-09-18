/**
 * Transaction context.
 *
 * Every repository method that reads or writes accepts a `Tx` as its first
 * parameter. `Tx` is opaque to the domain layer (typed as `unknown` here);
 * the Prisma-specific implementation narrows it to `Prisma.TransactionClient`
 * in the infrastructure adapter.
 *
 * Why opaque?
 *
 *   * The domain layer stays free of Prisma imports. Domain code can
 *     compose operations across multiple repositories inside a single
 *     transaction without ever mentioning Prisma.
 *
 *   * Use-cases that do NOT need transactions can pass the regular
 *     PrismaClient as `Tx` — both implement the same shape.
 *
 *   * We can swap ORMs (Drizzle, Kysely) without touching the domain.
 *
 * Convention for method signatures:
 *
 *     findById(tx: Tx, id: TId): Promise<TAggregate | null>
 *     save(tx: Tx, aggregate: TAggregate): Promise<TAggregate>
 *     delete(tx: Tx, id: TId): Promise<void>
 *
 * The `tx` is always the FIRST parameter after `this`, and is never
 * optional. Forgetting to thread it through is a code-review smell.
 */
export type Tx = unknown;
