import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { SessionRevoked } from '../../domain/events/auth.events';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';
import { RefreshTokenHash } from '../../domain/value-objects/refresh-token-hash';
import { SessionId } from '../../domain/value-objects/session-id';

export interface LogoutInput {
  /** Plaintext refresh token from the cookie / request body. */
  refreshToken: string;
}

/**
 * Log out: revoke the session identified by the presented refresh token.
 *
 * Idempotent — if the session is already revoked, the call is a no-op
 * success.
 */
@Injectable()
export class LogoutUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
  ) {}

  public async execute(input: LogoutInput): Promise<void> {
    const presentedHash = await RefreshTokenHash.fromPlaintext(
      input.refreshToken,
    );

    const revoked = await this.txRunner.run<{
      sessionId: SessionId;
      userId: UserId;
      alreadyRevoked: boolean;
    } | null>(async (tx: Tx) => {
      const session = await this.sessionRepo.findByRefreshHash(
        tx,
        presentedHash.value,
      );
      if (!session) {
        return null;
      }
      if (session.revokedAt !== null) {
        return {
          sessionId: session.id,
          userId: session.userId,
          alreadyRevoked: true,
        };
      }
      const saved = await this.sessionRepo.save(
        tx,
        session.revoke(this.clock, 'USER_LOGOUT'),
      );
      return {
        sessionId: saved.id,
        userId: saved.userId,
        alreadyRevoked: false,
      };
    });

    if (!revoked || revoked.alreadyRevoked) return;

    await this.eventBus.publishAll([
      new SessionRevoked(
        this.idGenerator.generate(),
        this.clock.now(),
        revoked.sessionId,
        revoked.userId,
        'USER_LOGOUT',
      ),
    ]);
  }
}
