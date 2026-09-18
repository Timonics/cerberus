import { DomainError } from '../../../shared/domain';
import { LoginAttemptWindow } from '../ports/login-attempt.repository.port';

/**
 * Lockout policy.
 *
 * Decides whether a login attempt should be rejected up-front based on
 * the current failure window. Pure function — no I/O. Configurable via
 * the constructor.
 *
 * Default thresholds (OWASP Authentication Best Practices §4.0):
 *   * 5 failures within 15 minutes → 15-minute lockout
 *   * 10 failures within 60 minutes → 60-minute lockout
 *   * Beyond → 24-hour lockout
 *
 * The exponential tiers are deliberate: short lockouts let legitimate
 * users back in fast, long lockouts make brute-force economically
 * unattractive.
 */
export class LockoutPolicy {
  public constructor(
    private readonly tiers: ReadonlyArray<{
      failures: number;
      windowSeconds: number;
      lockoutSeconds: number;
    }> = [
      { failures: 5, windowSeconds: 15 * 60, lockoutSeconds: 15 * 60 },
      { failures: 10, windowSeconds: 60 * 60, lockoutSeconds: 60 * 60 },
      {
        failures: 20,
        windowSeconds: 24 * 60 * 60,
        lockoutSeconds: 24 * 60 * 60,
      },
    ],
  ) {}

  /**
   * Returns the lockout duration (in seconds) the credential should be
   * locked for, given the current failure window. Returns `null` if no
   * lockout applies.
   *
   * If a lockout applies, the caller MUST also mark the credential's
   * `lockedUntil` field in the same transaction (so the database and the
   * in-Redis counter agree on the lockout).
   */
  public computeLockout(window: LoginAttemptWindow, now: Date): number | null {
    // Tiers are checked largest-first — the most severe applicable tier wins.
    const sortedTiers = [...this.tiers].sort((a, b) => b.failures - a.failures);
    for (const tier of sortedTiers) {
      // Count only failures within the tier's window.
      if (window.lastFailureAt === null) continue;
      const ageSeconds =
        (now.getTime() - window.lastFailureAt.getTime()) / 1000;
      if (ageSeconds > tier.windowSeconds) continue;
      if (window.count >= tier.failures) {
        return tier.lockoutSeconds;
      }
    }
    return null;
  }
}

/**
 * Convenience: throw a `locked` domain error if the lockout applies.
 */
export function assertNotLocked(
  policy: LockoutPolicy,
  window: LoginAttemptWindow,
  now: Date,
): void {
  const lockSeconds = policy.computeLockout(window, now);
  if (lockSeconds !== null) {
    const until = new Date(now.getTime() + lockSeconds * 1000);
    throw new DomainError(
      'authentication.account_locked',
      'Account temporarily locked due to repeated failed login attempts',
      { lockedUntil: until.toISOString() },
    );
  }
}
