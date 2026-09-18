import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  EVENT_BUS,
  EventBus,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';
import { PasswordChanged } from '../../../identity/domain/events/identity.events';

/**
 * Cross-context event handler: when a user's password changes, revoke
 * every active session for that user.
 *
 * Defense-in-depth: even if an attacker has a stolen session cookie,
 * rotating the password kicks them out everywhere.
 *
 * Subscribes via our own `EventBus.subscribe()` (NOT Nest's @OnEvent —
 * we don't want to add `@nestjs/event-emitter` as a dependency).
 */
@Injectable()
export class PasswordChangedSessionRevoker implements OnModuleInit {
  private readonly logger = new Logger(PasswordChangedSessionRevoker.name);

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    @Inject(EVENT_BUS) private readonly bus: EventBus,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe('identity.password.changed', async (event) => {
      if (event instanceof PasswordChanged) {
        await this.handle(event);
      }
    });
  }

  public async handle(event: PasswordChanged): Promise<void> {
    const userId = event.userId;
    try {
      const count = await this.txRunner.run<number>(async (tx: Tx) => {
        return this.sessionRepo.revokeAllForUser(
          tx,
          userId,
          'PASSWORD_CHANGED',
        );
      });
      this.logger.log(
        `Revoked ${count} active session(s) after password change for user ${userId.value}`,
      );
    } catch (err) {
      this.logger.error(
        `Failed to revoke sessions after password change for user ${userId.value}: ${String(err)}`,
      );
    }
  }
}
