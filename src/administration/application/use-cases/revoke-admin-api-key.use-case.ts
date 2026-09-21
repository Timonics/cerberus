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
  ADMIN_API_KEY_REPOSITORY,
  AdminApiKeyRepository,
} from '../../domain/ports/admin-api-key.repository.port';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

@Injectable()
export class RevokeAdminApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ADMIN_API_KEY_REPOSITORY)
    private readonly repo: AdminApiKeyRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(keyId: string): Promise<void> {
    const revoked = await this.txRunner.run<boolean>(async (tx: Tx) => {
      const existing = await this.repo.findById(tx, keyId);
      if (!existing) {
        throw new DomainError(
          'admin.api_key.not_found',
          'Admin API key not found',
          { keyId },
        );
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
        eventType: 'admin.api_key.revoked',
        payload: { keyId },
      });
    }
  }
}
