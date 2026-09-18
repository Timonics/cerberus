import { Inject, Injectable } from '@nestjs/common';
import {
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { Session } from '../../domain/aggregates/session';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';

export interface ListSessionsInput {
  userId: string;
}

export interface ListSessionsItem {
  sessionId: string;
  deviceLabel: string | null;
  ipAddress: string | null;
  issuedAt: Date;
  expiresAt: Date;
  lastUsedAt: Date | null;
}

export interface ListSessionsResult {
  sessions: ReadonlyArray<ListSessionsItem>;
}

/**
 * List the active sessions for a user. Used by the "Where you're signed
 * in" UI. Returns one entry per non-revoked, non-expired session.
 */
@Injectable()
export class ListSessionsUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
  ) {}

  public async execute(input: ListSessionsInput): Promise<ListSessionsResult> {
    const userId = UserId.create(input.userId);
    return this.txRunner.run<ListSessionsResult>(async (tx: Tx) => {
      const sessions = await this.sessionRepo.findActiveByUserId(tx, userId);
      return {
        sessions: sessions.map((s: Session) => ({
          sessionId: s.id.value,
          deviceLabel: s.deviceLabel,
          ipAddress: s.ipAddress?.value ?? null,
          issuedAt: s.issuedAt,
          expiresAt: s.expiresAt,
          lastUsedAt: s.lastUsedAt,
        })),
      };
    });
  }
}
