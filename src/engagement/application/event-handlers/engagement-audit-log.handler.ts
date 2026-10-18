import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EVENT_BUS, EventBus } from '../../../shared/domain';
import {
  EmailVerificationConsumed,
  EmailVerificationRequested,
  PasswordResetConsumed,
  PasswordResetRequested,
} from '../../domain/events/engagement.events';
import { RecordAuditEventUseCase } from '../use-cases/record-audit-event.use-case';

/**
 * Cross-context audit-log handler for engagement events.
 *
 * Wires four event types from the in-process bus to the
 * `audit_log` table so security teams can answer:
 *   - When was a verification email sent?
 *   - When did the user click the link?
 *   - When was a password reset email sent?
 *   - When did the user complete the reset?
 *
 * V1.5 audit-completion fix: previously these events fired but no
 * subscriber wrote to the audit log — the four engagement event
 * types existed in AUDIT_EVENT_TYPES but were never recorded.
 *
 * Failures are logged but never throw — the audit log is a
 * downstream consumer and shouldn't break the user-facing flow.
 */
@Injectable()
export class EngagementAuditLogHandler implements OnModuleInit {
  private readonly logger = new Logger(EngagementAuditLogHandler.name);

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe(
      'engagement.email_verification.requested',
      async (event) => {
        if (event instanceof EmailVerificationRequested) {
          await this.record({
            userId: event.userId,
            eventType: 'engagement.email_verification.requested',
            payload: { verificationId: event.verificationId },
          });
        }
      },
    );
    this.bus.subscribe(
      'engagement.email_verification.completed',
      async (event) => {
        if (event instanceof EmailVerificationConsumed) {
          await this.record({
            userId: event.userId,
            eventType: 'engagement.email_verification.completed',
            payload: { verificationId: event.verificationId },
          });
        }
      },
    );
    this.bus.subscribe('engagement.password_reset.requested', async (event) => {
      if (event instanceof PasswordResetRequested) {
        await this.record({
          userId: event.userId,
          eventType: 'engagement.password_reset.requested',
          payload: { resetId: event.resetId },
        });
      }
    });
    this.bus.subscribe('engagement.password_reset.completed', async (event) => {
      if (event instanceof PasswordResetConsumed) {
        await this.record({
          userId: event.userId,
          eventType: 'engagement.password_reset.completed',
          payload: { resetId: event.resetId },
        });
      }
    });
  }

  private async record(input: {
    userId: string;
    eventType: string;
    payload: Readonly<Record<string, unknown>>;
  }): Promise<void> {
    try {
      await this.recordAuditEventUc.execute(input);
    } catch (err) {
      // V1.7 audit fix #31: P2002 = unique constraint violation.
      // Means we already wrote this row — the outbox relay re-
      // published a previously-processed event. Safe to ignore.
      const message = err instanceof Error ? err.message : String(err);
      if (/P2002|Unique constraint/i.test(message)) {
        this.logger.debug(
          `audit-log dedup: ${input.eventType} already recorded`,
        );
        return;
      }
      this.logger.error(
        `Failed to record audit event [${input.eventType}] for user ${input.userId}: ${message}`,
      );
    }
  }
}
