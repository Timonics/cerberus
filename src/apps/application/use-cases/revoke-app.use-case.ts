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
  ) {}

  public async execute(appId: string): Promise<void> {
    await this.txRunner.run<void>(async (tx: Tx) => {
      const existing = await this.repo.findById(tx, appId);
      if (!existing) {
        throw new DomainError('app.not_found', 'App not found', { appId });
      }
      if (existing.revokedAt !== null) {
        return; // idempotent
      }
      const revoked = existing.revoke(this.clock);
      await this.repo.save(tx, revoked);
    });
  }
}
