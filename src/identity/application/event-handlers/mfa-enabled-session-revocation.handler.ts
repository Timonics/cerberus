import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  EVENT_BUS,
  EventBus,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';
import { MfaEnabled } from '../../domain/events/identity.events';

/**
 * Cross-context event handler (2026-10-19 audit MEDIUM): when a user
 * completes MFA enrollment, revoke every OTHER active session for
 * that user.
 *
 * Rationale: enabling MFA after a suspected compromise previously
 * left attacker sessions alive for up to 30 days; token theft could
 * also be converted into persistent MFA lockout. Rotating the
 * session set at enrollment bounds the exposure.
 *
 * "Current session" identification: REST requests carry no session
 * binding in the access JWT, so the session the user just enrolled
 * from cannot be named directly. We keep the MOST RECENTLY ACTIVE
 * session (lastUsedAt, falling back to issuedAt) and revoke the rest.
 * `Session.revoke` only offers the shared `RevokeReason` enum; the
 * closest fit for a security-driven mass revocation is
 * `ADMIN_REVOKED`.
 *
 * Subscribes via our own `EventBus.subscribe()` (not Nest's
 * `@OnEvent`) to match the other cross-context handlers.
 */
@Injectable()
export class MfaEnabledSessionRevoker implements OnModuleInit {
  private readonly logger = new Logger(MfaEnabledSessionRevoker.name);

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe('identity.mfa.enabled', async (event) => {
      if (event instanceof MfaEnabled) {
        await this.handle(event);
      }
    });
  }

  public async handle(event: MfaEnabled): Promise<void> {
    const userId = event.userId;
    try {
      const revoked = await this.txRunner.run<number>(async (tx: Tx) => {
        const sessions = await this.sessionRepo.findActiveByUserId(tx, userId);
        if (sessions.length <= 1) {
          return 0;
        }

        // Keep the most recently active session (the enrollment is
        // expected to have happened on it); revoke the rest.
        const keep = sessions.reduce((a, b) =>
          this.lastActivity(b) > this.lastActivity(a) ? b : a,
        );
        let count = 0;
        for (const session of sessions) {
          if (session.id.value === keep.id.value) continue;
          await this.sessionRepo.save(
            tx,
            session.revoke(this.clock, 'ADMIN_REVOKED'),
          );
          count += 1;
        }
        return count;
      });
      if (revoked > 0) {
        this.logger.log(
          `Revoked ${revoked} other session(s) after MFA enablement for user ${userId.value}`,
        );
      }
    } catch (err) {
      this.logger.error(
        `Failed to revoke sessions after MFA enablement for user ${userId.value}: ${String(err)}`,
      );
    }
  }

  private lastActivity(session: {
    lastUsedAt: Date | null;
    issuedAt: Date;
  }): number {
    return (session.lastUsedAt ?? session.issuedAt).getTime();
  }
}
