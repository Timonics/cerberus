import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

/**
 * Revoke an app.
 *
 * Soft-revoke (sets `revokedAt`). Future requests with any of the
 * app's keys fail at the guard with `app.revoked`.
 */
@Injectable()
export class RevokeAppUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(APP_REPOSITORY) private readonly repo: AppRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(appId: string): Promise<void> {
    const revoked = await this.txRunner.run<boolean>(async (tx: Tx) => {
      const existing = await this.repo.findById(tx, appId);
      if (!existing) {
        throw new DomainError('app.not_found', 'App not found', { appId });
      }
      if (existing.revokedAt !== null) {
        return false; // already revoked (idempotent)
      }
      const updated = existing.revoke(this.clock);
      await this.repo.save(tx, updated);
      return true;
    });
    if (revoked) {
      await this.recordAuditEventUc.execute({
        userId: null,
        eventType: 'apps.app.revoked',
        payload: { appId },
      });
    }
  }
}
