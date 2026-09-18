/**
 * Clock port.
 *
 * The domain layer must never call `new Date()` or `Date.now()` directly.
 * Doing so makes the time of an event non-deterministic and untestable.
 * Instead, every aggregate and use-case takes a `Clock` and calls
 * `clock.now()`. The default adapter returns real wall-clock time; tests
 * substitute a fake that returns controlled values.
 */
export interface Clock {
  /** Current wall-clock time in UTC. */
  now(): Date;
}

export const CLOCK = Symbol('Clock');
