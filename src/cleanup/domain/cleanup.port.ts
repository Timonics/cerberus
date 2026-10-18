/**
 * Cleanup port — single seam between the use-case and the storage
 * adapter. The use-case calls `cleanup()` once; the adapter fans out
 * to per-table deletes and returns a count map.
 *
 * The port is intentionally aggregate-free: cleanup is a cross-context
 * concern, not a domain operation. Tests can stub it without booting
 * the full Prisma graph.
 */
export interface CleanupResult {
  /** Rows deleted, keyed by table name. */
  readonly deleted: Readonly<Record<string, number>>;
  /** Wall-clock duration of the cleanup pass in milliseconds. */
  readonly durationMs: number;
}

export abstract class CleanupRepository {
  public abstract cleanup(ttls: CleanupTtls): Promise<CleanupResult>;
}

/**
 * TTL config (in days, except the two fields measured in hours).
 * Each field defaults to 0 = "no cleanup"; setting a positive value
 * keeps rows for that grace window past their expiry before deleting.
 */
export interface CleanupTtls {
  emailVerificationTtlHours: number;
  passwordResetTtlHours: number;
  invitationTtlDays: number;
  sessionTtlDays: number;
  appKeyTtlDays: number;
  adminKeyTtlDays: number;
  signingKeyTtlDays: number;
  recoveryCodeTtlDays: number;
  outboxTtlDays: number;
  // V1.7 audit fix #38: GDPR-bounded retention for audit_logs.
  // IP addresses are PII; default 90 days matches common SOC2 +
  // ISO 27001 event-log retention windows. Set to 0 to disable.
  auditLogTtlDays: number;
}

export const CLEANUP_REPOSITORY = Symbol('CleanupRepository');
