/**
 * Login-attempt repository port.
 *
 * Backed by Redis (V sliding window) so it can be hot-pathed without
 * hitting Postgres. Keys are scoped per (email, ip) tuple — a brute-
 * forcer targeting one account from one IP triggers the lockout — and
 * per email alone (2026-10-19 audit fix H-8: any-IP cumulative counter
 * so distributed attacks from rotating IPs also trip the lockout).
 *
 * Sliding window: we store the timestamp of each failed attempt in a
 * Redis sorted set, score = epoch ms. Old entries are evicted on every
 * write. The failure count is the size of the set after eviction.
 *
 * Successful logins clear the windows (no need to keep tracking after
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

  /**
   * 2026-10-19 audit fix H-8: per-email cumulative failure counter
   * (any IP). The per-(email, ip) window stops the single-IP
   * brute-forcer; this counter stops the distributed one — an
   * attacker rotating IPs never accumulates 5 failures under any
   * one (email, ip) key, but every failure lands in this bucket.
   */
  public abstract recordAccountFailure(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow>;

  /** Read the per-email (any-IP) window without recording. */
  public abstract getAccountWindow(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<LoginAttemptWindow>;

  /** Clear the per-email (any-IP) window after a successful login. */
  public abstract clearAccount(email: string): Promise<void>;

  /**
   * 2026-10-19 audit fix H-12: record one MFA-pending challenge
   * issuance (a correct-password login against an MFA-enabled account
   * that is about to receive an mfaToken). Returns the number of
   * issuances in the window AFTER this one. LoginUseCase blocks the
   * response once the count exceeds the hourly limit so the
   * correct-password-vs-wrong-password signal cannot be farmed.
   */
  public abstract recordMfaPendingIssuance(
    email: string,
    now: Date,
    windowSeconds: number,
  ): Promise<number>;
}

export const LOGIN_ATTEMPT_REPOSITORY = Symbol('LoginAttemptRepository');
