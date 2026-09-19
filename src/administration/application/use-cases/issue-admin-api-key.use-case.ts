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
import {
  AdminApiKey,
  generateAdminApiKeyPlaintext,
} from '../../domain/aggregates/admin-api-key';
import {
  ADMIN_API_KEY_REPOSITORY,
  AdminApiKeyRepository,
} from '../../domain/ports/admin-api-key.repository.port';
import { AdminApiKeyHasher } from '../../infrastructure/security/argon2-admin-api-key.hasher';

export interface IssueAdminApiKeyInput {
  name: string;
  createdBy: string;
  ttlSeconds: number;
  notes?: string;
}

export interface IssueAdminApiKeyResult {
  key: AdminApiKey;
  /** Plaintext token — returned exactly once, never retrievable. */
  plaintextToken: string;
}

/**
 * Issue a new admin API key.
 *
 * Generates a 32-byte random plaintext, hashes it with argon2id,
 * persists the aggregate (with hash + metadata) and returns BOTH the
 * aggregate and the plaintext. The caller is responsible for
 * surfacing the plaintext to the operator exactly once — it is not
 * retrievable after this use-case returns.
 */
@Injectable()
export class IssueAdminApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(ADMIN_API_KEY_REPOSITORY)
    private readonly repo: AdminApiKeyRepository,
    private readonly hasher: AdminApiKeyHasher,
  ) {}

  public async execute(
    input: IssueAdminApiKeyInput,
  ): Promise<IssueAdminApiKeyResult> {
    const plaintextToken = generateAdminApiKeyPlaintext();
    const keyHash = await this.hasher.hash(plaintextToken);

    const key = await this.txRunner.run<AdminApiKey>(async (tx: Tx) => {
      const k = AdminApiKey.issue({
        id: this.idGenerator.generate(),
        name: input.name,
        plaintextToken,
        keyHash,
        role: 'ADMIN',
        createdBy: input.createdBy,
        clock: this.clock,
        ttlSeconds: input.ttlSeconds,
        notes: input.notes,
      });
      return this.repo.save(tx, k);
    });

    void this.eventBus; // reserved for V1.5 audit-event fan-out

    return { key, plaintextToken };
  }
}
