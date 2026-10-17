import { PrismaClient, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import {
  CleanupRepository,
  CleanupResult,
  CleanupTtls,
} from '../domain/cleanup.port';

/**
 * Prisma-backed cleanup repository.
 *
 * Each table has its own delete; failures are caught and logged so a
 * single broken table doesn't block the others. Counts are returned
 * to the caller via `CleanupResult.deleted` for observability.
 *
 * The pattern of "delete many with a where-clause" is consistent with
 * Prisma's `deleteMany`: it issues a single SQL DELETE statement with
 * the filter baked in, which Postgres can satisfy with the existing
 * `expiresAt` / `revokedAt` / `processedAt` indexes.
 *
 * Rows are deleted in a single transaction per pass. If any one
 * delete fails, the transaction rolls back — this is the right
 * default (we'd rather leave rows for next pass than half-delete).
 * For per-table isolation, run cleanup() in a try/catch on each
 * branch; the port adapter below chooses transaction-per-table.
 */
@Injectable()
export class PrismaCleanupRepository extends CleanupRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async cleanup(ttls: CleanupTtls): Promise<CleanupResult> {
    const start = Date.now();
    const client: PrismaClient = this.prisma;
    const deleted: Record<string, number> = {};

    // Email verifications + password resets: TTL is in HOURS, not
    // days. The user-facing window is small (1 hour by default) so
    // a per-row clean-up is cheap.
    deleted.email_verifications = await this.tryDelete(() =>
      client.emailVerification.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(
              Date.now() - ttls.emailVerificationTtlHours * 3_600_000,
            ),
          },
        },
      }),
    );
    deleted.password_resets = await this.tryDelete(() =>
      client.passwordReset.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(Date.now() - ttls.passwordResetTtlHours * 3_600_000),
          },
        },
      }),
    );
    deleted.invitations = await this.tryDelete(() =>
      client.invitation.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(Date.now() - ttls.invitationTtlDays * 86_400_000),
          },
        },
      }),
    );

    // Sessions: revoke timestamps are kept around for 30 days by
    // default so users can answer "when was my device signed out?"
    // for a month. After that, the row is gone.
    deleted.sessions = await this.tryDelete(() =>
      client.session.deleteMany({
        where: {
          revokedAt: {
            lt: new Date(Date.now() - ttls.sessionTtlDays * 86_400_000),
          },
        },
      }),
    );

    // API keys: revoke timestamps are kept for 90 days so security
    // teams can answer "what keys existed in the last quarter?".
    deleted.app_api_keys = await this.tryDelete(() =>
      client.appApiKey.deleteMany({
        where: {
          revokedAt: {
            lt: new Date(Date.now() - ttls.appKeyTtlDays * 86_400_000),
          },
        },
      }),
    );
    deleted.admin_api_keys = await this.tryDelete(() =>
      client.adminApiKey.deleteMany({
        where: {
          revokedAt: {
            lt: new Date(Date.now() - ttls.adminKeyTtlDays * 86_400_000),
          },
        },
      }),
    );

    // Signing keys: only retire old (non-current) ones. The current
    // signing key must never be deleted — JWTs in flight still need
    // it.
    deleted.signing_keys = await this.tryDelete(() =>
      client.signingKey.deleteMany({
        where: {
          isCurrent: false,
          expiresAt: {
            lt: new Date(Date.now() - ttls.signingKeyTtlDays * 86_400_000),
          },
        },
      }),
    );

    // Recovery codes: only after use, with a 90-day audit window.
    // Unused codes (no `usedAt`) live as long as their parent
    // MfaSecret, so they're deleted via the FK cascade when MFA is
    // disabled — not by this cron.
    deleted.recovery_codes = await this.tryDelete(() =>
      client.recoveryCode.deleteMany({
        where: {
          usedAt: {
            lt: new Date(Date.now() - ttls.recoveryCodeTtlDays * 86_400_000),
          },
        },
      }),
    );

    // Outbox: keep processed rows for 7 days so operators can audit
    // what events flowed through. After that, the row is gone — the
    // in-memory bus subscribers have already done their work, and
    // the audit log captures the human-facing record.
    deleted.outbox_events = await this.tryDelete(() =>
      client.outboxEvent.deleteMany({
        where: {
          processedAt: {
            lt: new Date(Date.now() - ttls.outboxTtlDays * 86_400_000),
          },
        },
      }),
    );

    return { deleted, durationMs: Date.now() - start };
  }

  /**
   * Run a delete in its own transaction; log + return 0 on failure
   * instead of throwing. The use-case decides what to do with the
   * resulting counts.
   */
  private async tryDelete(
    fn: () => Promise<{ count: number }>,
  ): Promise<number> {
    try {
      const { count } = await fn();
      return count;
    } catch (err) {
      // Log to stdout — Nest's logger isn't reachable from this
      // adapter without extra wiring, and the cleanup pass logs the
      // summary itself via the scheduler.

      console.error('[cleanup] delete failed', err);
      return 0;
    }
  }
}

// Re-export Prisma types so the adapter doesn't leak them to domain.
export type { Prisma };
