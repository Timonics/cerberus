/**
 * Login-attempt repository port.
 *
 * Backed by Redis (V sliding window) so it can be hot-pathed without
 * hitting Postgres. Keys are scoped per (email, ip) tuple — a brute-
 * forcer targeting one account from one IP triggers the lockout.
 *
 * Sliding window: we store the timestamp of each failed attempt in a
 * Redis sorted set, score = epoch ms. Old entries are evicted on every
 * write. The failure count is the size of the set after eviction.
 *
 * Successful logins clear the window (no need to keep tracking after
 * the user proved they own the account).
 */
export interface LoginAttemptWindow {
  /** Number of failures in the current window. */
  readonly count: number;
  /** Timestamp of the most recent failure, or null if no failures. */
  readonly lastFailureAt: Date | null;
}

export abstract class LoginAttemptRepository {
  /**
   * Record a failed login attempt. Returns the updated window state
   * AFTER the new entry is added.
   */
  public abstract recordFailure(
    email: string,
    ip: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow>;

  /** Clear the window — called after a successful login. */
  public abstract clear(email: string, ip: string): Promise<void>;

  /** Read the current window without recording anything. */
  public abstract getWindow(
    email: string,
    ip: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow>;
}

export const LOGIN_ATTEMPT_REPOSITORY = Symbol('LoginAttemptRepository');
