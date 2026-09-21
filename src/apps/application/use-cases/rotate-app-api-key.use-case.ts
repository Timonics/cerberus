import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { App, generateAppApiKeyPlaintext } from '../../domain/aggregates/app';
import { AppApiKey } from '../../domain/aggregates/app-api-key';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';
import { Argon2AppApiKeyHasher } from '../../infrastructure/security/argon2-app-api-key.hasher';

export interface RotateAppApiKeyResult {
  app: App;
  plaintextApiKey: string;
}

/**
 * Mint a new API key for an existing app.
 *
 * V1: the OLD key continues to work after rotation (we don't auto-revoke).
 * The caller is expected to deploy the new key and then call
 * `RevokeAppApiKeyUseCase` (V1.5) once the old key is decommissioned.
 *
 * V1.5: auto-revoke the previous key in the same transaction.
 */
@Injectable()
export class RotateAppApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(APP_REPOSITORY) private readonly repo: AppRepository,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
    private readonly hasher: Argon2AppApiKeyHasher,
  ) {}

  public async execute(
    appId: string,
    ttlSeconds: number,
  ): Promise<RotateAppApiKeyResult> {
    const plaintextToken = generateAppApiKeyPlaintext();
    const keyHash = await this.hasher.hash(plaintextToken);

    const app = await this.txRunner.run<App>(async (tx: Tx) => {
      const existing = await this.repo.findById(tx, appId);
      if (!existing) {
        throw new DomainError('app.not_found', 'App not found', { appId });
      }
      if (existing.revokedAt !== null) {
        throw new DomainError(
          'app.revoked',
          'Cannot rotate keys on a revoked app',
          { appId },
        );
      }
      const newKey = AppApiKey.issue({
        id: this.idGenerator.generate(),
        appId: existing.id,
        plaintextToken,
        keyHash,
        name: `${existing.name} rotated key`,
        clock: this.clock,
        ttlSeconds,
      });
      const updated = existing.rotateKey(newKey);
      return this.repo.save(tx, updated);
    });

    // Audit: apps.app.key_rotated.
    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'apps.app.key_rotated',
      payload: { appId: app.id },
    });

    return { app, plaintextApiKey: plaintextToken };
  }
}
