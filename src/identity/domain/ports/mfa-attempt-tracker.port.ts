/**
 * MFA verification attempt tracker (outbound port).
 *
 * 2026-10-19 audit fix H-5b: `mfa/verify` previously had no failure
 * counter and no lockout — an attacker holding a pre-MFA credential
 * got unlimited online guesses at a 10⁶ TOTP space. This port backs
 * the per-(userId, sessionId) counter: 5 failures within the window
 * locks the pair out for 15 minutes.
 *
 * Implementations MUST be race-safe (Redis INCR/SETNX semantics).
 */
export abstract class MfaAttemptTracker {
  /** True when the (userId, sessionId) pair is currently locked out. */
  public abstract isLocked(userId: string, sessionId: string): Promise<boolean>;

  /**
   * Record a failed verification attempt. Returns the failure count
   * within the current window so the caller can decide when to lock.
   */
  public abstract recordFailure(
    userId: string,
    sessionId: string,
  ): Promise<number>;

  /** Lock the pair out for `ttlSeconds`. Idempotent. */
  public abstract lock(
    userId: string,
    sessionId: string,
    ttlSeconds: number,
  ): Promise<void>;

  /** Clear the failure window after a successful verification. */
  public abstract clearFailures(
    userId: string,
    sessionId: string,
  ): Promise<void>;
}

export const MFA_ATTEMPT_TRACKER = Symbol('MfaAttemptTracker');
