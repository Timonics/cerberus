/**
 * Public surface of the shared domain kernel.
 *
 * Consumers should import from this barrel rather than from individual files.
 * That way:
 *
 *   * Renames inside `shared/domain` are non-breaking.
 *   * We can lint this barrel to ensure no infrastructure types leak out.
 *   * Domain code stays portable across bounded contexts.
 */

export * from './errors/domain-error';
export * from './events/domain-event';
export * from './events/event-bus.port';
export * from './clock/clock.port';
export * from './ids/id-generator.port';
export * from './value-objects/email';
export * from './value-objects/password';
export * from './value-objects/password-hash';
export * from './value-objects/entity-id';
export * from './persistence/tx';
export * from './persistence/base-repository';
export * from './persistence/transaction-runner.port';
