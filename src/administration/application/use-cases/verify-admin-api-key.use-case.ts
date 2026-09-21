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
import { AdminApiKeyLookupTokenService } from '../../infrastructure/security/admin-api-key-lookup-token.service';

export interface VerifyAdminApiKeyInput {
  plaintextToken: string;
}

export interface VerifyAdminApiKeyResult {
  adminKeyId: string;
  role: 'ADMIN' | 'SUPER_ADMIN';
}

/**
 * Verify an admin API key presented in an `Authorization: Bearer *** header.
 *
 * V1.5 (audit C5): was O(N) — scanned all admin keys and ran argon2
 * verify on each. With 100 keys, that was ~5s per admin request. Now:
 *   1. Compute the lookup token (HMAC-SHA256 of the plaintext).
 *   2. Find the candidate row by UNIQUE INDEX on lookupToken (O(1)).
 *   3. Run argon2 verify on the candidate's keyHash (one verify).
 *   4. If verify passes and the key is alive, mark used and return.
 *
 * V1.5 (audit H2): the `lastUsedAt` write was previously fire-and-forget
 * via `void this.txRunner.run(...)` — if the request returned before
 * the write completed, the write could be lost on shutdown. Now the
 * mark-used write runs in the SAME transaction as the verification
 * lookup (or after it, but awaited).
 */
@Injectable()
export class VerifyAdminApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ADMIN_API_KEY_REPOSITORY)
    private readonly repo: AdminApiKeyRepository,
    private readonly hasher: AdminApiKeyHasher,
    private readonly lookupTokenSvc: AdminApiKeyLookupTokenService,
  ) {}

  public async execute(
    input: VerifyAdminApiKeyInput,
  ): Promise<VerifyAdminApiKeyResult | null> {
    if (!input.plaintextToken || !input.plaintextToken.trim()) {
      return null;
    }
    const plaintext = input.plaintextToken.trim();
    const lookupToken = this.lookupTokenSvc.compute(plaintext);

    // Two-step lookup:
    //   * findActiveByLookupToken — match on lookupToken AND not
    //     revoked AND not expired. If null, try the ignoring-expiry
    //     path so we can distinguish unknown vs revoked vs expired.
    //   * findActiveByLookupTokenIgnoringExpiry — same lookup but no
    //     expiry filter, used to disambiguate "expired" in the audit log.
    const candidate = await this.txRunner.run(async (tx: Tx) =>
      this.repo.findActiveByLookupToken(tx, lookupToken),
    );
    if (!candidate) {
      // Disambiguate: unknown key vs revoked/expired.
      const any = await this.txRunner.run(async (tx: Tx) =>
        this.repo.findByLookupTokenIgnoringExpiry(tx, lookupToken),
      );
      if (any) {
        if (any.revokedAt !== null) {
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
      return null;
    }

    // Single argon2 verify on the candidate row.
    const ok = await this.hasher.verify(candidate.keyHash, plaintext);
    if (!ok) {
      // This shouldn't happen — lookupToken is HMAC-derived from the
      // plaintext, so a token that hashes to the row's lookupToken
      // should also argon2-verify. But if HMAC and argon2 ever
      // diverge (key rotation, clock skew, etc.), treat as unknown.
      return null;
    }

    // Mark used in the SAME transaction — no more fire-and-forget.
    const updated = await this.txRunner.run(async (tx: Tx) =>
      this.repo.markUsed(tx, candidate.id, this.clock.now()),
    );

    return {
      adminKeyId: updated.id,
      role: updated.role.value,
    };
  }
}
