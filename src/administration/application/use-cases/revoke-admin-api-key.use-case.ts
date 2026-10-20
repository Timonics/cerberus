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
      // Audit 2026-10-19 (admin LOW): refuse to revoke the last ACTIVE
      // admin key. A leaked CI key must not be able to lock the
      // operator out of the admin surface entirely (recovery would need
      // DB surgery). Note: `existing` is ACTIVE here (revokedAt is
      // null), so activeCount === 1 means it's the last one.
      const all = await this.repo.listAll(tx);
      const activeCount = all.filter((k) =>
        k.isAliveAt(this.clock.now()),
      ).length;
      if (activeCount <= 1) {
        throw new DomainError(
          'admin.key.last_active',
          'Refusing to revoke the last active admin API key — issue a replacement key first',
          { keyId },
        );
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
