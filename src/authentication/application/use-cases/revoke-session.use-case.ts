import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
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
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';
import { SessionId } from '../../domain/value-objects/session-id';

export interface RevokeSessionInput {
  sessionId: string;
  /** The calling user. Used to ensure they can only revoke their OWN sessions. */
  requesterUserId: string;
}

export type RevokeReasonCode =
  | 'USER_LOGOUT'
  | 'PASSWORD_CHANGED'
  | 'ADMIN_REVOKED'
  | 'FAMILY_COMPROMISED'
  | 'EXPIRED';

/**
 * Revoke a specific session.
 *
 * Authorization rule: the caller must own the session OR be an admin.
 * V1 only supports the "own" path — admin revocation lands in Phase 15
 * (Administration context).
 */
@Injectable()
export class RevokeSessionUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
  ) {}

  public async execute(input: RevokeSessionInput): Promise<void> {
    const sessionId = SessionId.create(input.sessionId);
    const requesterId = UserId.create(input.requesterUserId);

    const result = await this.txRunner.run<{
      sessionId: SessionId;
      userId: UserId;
      alreadyRevoked: boolean;
    } | null>(async (tx: Tx) => {
      const session = await this.sessionRepo.findById(tx, sessionId);
      if (!session) {
        return null;
      }
      // Ownership check: refuse to revoke someone else's session.
      if (!session.userId.equals(requesterId)) {
        throw new DomainError(
          'authentication.session.not_found',
          'Session not found',
        );
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

    if (!result) {
      throw new DomainError(
        'authentication.session.not_found',
        'Session not found',
      );
    }
    if (result.alreadyRevoked) return;

    await this.eventBus.publishAll([
      new SessionRevoked(
        this.idGenerator.generate(),
        this.clock.now(),
        result.sessionId,
        result.userId,
        'USER_LOGOUT',
      ),
    ]);

    // Audit: authentication.session.revoked.
    await this.recordAuditEventUc.execute({
      userId: result.userId.value,
      eventType: 'authentication.session.revoked',
      payload: {
        sessionId: result.sessionId.value,
        revokedBy: 'USER_LOGOUT',
        requesterUserId: input.requesterUserId,
      },
    });
  }
}
