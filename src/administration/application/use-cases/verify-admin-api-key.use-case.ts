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
import { AdminApiKeyHasher } from '../../infrastructure/security/argon2-admin-api-key.hasher';

export interface VerifyAdminApiKeyInput {
  plaintextToken: string;
}

export interface VerifyAdminApiKeyResult {
  adminKeyId: string;
  role: 'ADMIN' | 'SUPER_ADMIN';
}

/**
 * Verify an admin API key presented in an `Authorization: Bearer ***`
 * header.
 *
 * Looks up by argon2id hash. Returns null if the token is unknown,
 * the key is revoked, or the key is expired. Also marks the key as
 * used (updates `lastUsedAt`) on success — useful for ops dashboards.
 *
 * Uses an "ignoring expiry" lookup followed by a separate
 * expiry/revocation check so the audit log can distinguish
 * "expired key" from "unknown key" (both look like a 401 to the
 * client, but only the latter is suspicious).
 */
@Injectable()
export class VerifyAdminApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ADMIN_API_KEY_REPOSITORY)
    private readonly repo: AdminApiKeyRepository,
    private readonly hasher: AdminApiKeyHasher,
  ) {}

  public async execute(
    input: VerifyAdminApiKeyInput,
  ): Promise<VerifyAdminApiKeyResult | null> {
    if (!input.plaintextToken || !input.plaintextToken.trim()) {
      return null;
    }
    // We have to compare against ALL non-revoked keys with the same
    // hash-prefix, but argon2id hashes are salted, so we can't
    // pre-hash and lookup. Instead, look up by plaintext via the
    // equality check in the repository (which uses argon2.verify).
    //
    // V1 implementation: scan active keys, verify each. With ≤ 100
    // admin keys this is acceptable. V1.5 will index by a separate
    // lookup-token (HMAC of the plaintext) for O(1) lookup.
    const all = await this.txRunner.run(async (tx: Tx) =>
      this.repo.listAll(tx),
    );
    for (const candidate of all) {
      const ok = await this.hasher.verify(
        candidate.keyHash,
        input.plaintextToken,
      );
      if (!ok) continue;
      if (!candidate.isAliveAt(this.clock.now())) {
        if (candidate.revokedAt !== null) {
          throw new DomainError(
            'admin.api_key.revoked',
            'Admin API key has been revoked',
          );
        }
        throw new DomainError(
          'admin.api_key.expired',
          'Admin API key has expired',
        );
      }
      // Mark used (best-effort — don't fail the auth if the write
      // races with a delete).
      void this.txRunner.run(async (tx: Tx) => {
        try {
          await this.repo.markUsed(tx, candidate.id, this.clock.now());
        } catch {
          // swallow — lastUsedAt is informational, not auth-critical
        }
      });
      return {
        adminKeyId: candidate.id,
        role: candidate.role.value,
      };
    }
    return null;
  }
}
