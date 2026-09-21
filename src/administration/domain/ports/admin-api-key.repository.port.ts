import { Tx } from '../../../shared/domain';
import { AdminApiKey } from '../aggregates/admin-api-key';

export abstract class AdminApiKeyRepository {
  public abstract findById(tx: Tx, id: string): Promise<AdminApiKey | null>;

  /**
   * Find by the plaintext token. Returns null if no key matches OR if
   * the matched key is revoked or expired. The use-case then asks the
   * aggregate to verify the token via `verify()`.
   */
  public abstract findActiveByPlaintextHash(
    tx: Tx,
    tokenHash: string,
  ): Promise<AdminApiKey | null>;

  public abstract findActiveByPlaintextHashIgnoringExpiry(
    tx: Tx,
    tokenHash: string,
  ): Promise<AdminApiKey | null>;

  /**
   * V1.5: O(1) lookup by HMAC-derived lookup token. Replaces the O(N)
   * plaintext-hash scan that was vulnerable to timing oracles + DoS.
   * Returns null if no key matches OR if the matched key is revoked
   * or expired.
   */
  public abstract findActiveByLookupToken(
    tx: Tx,
    lookupToken: string,
  ): Promise<AdminApiKey | null>;

  /**
   * V1.5: same lookup but ignores expiry — used to disambiguate
   * "expired" from "unknown" in the audit log.
   */
  public abstract findByLookupTokenIgnoringExpiry(
    tx: Tx,
    lookupToken: string,
  ): Promise<AdminApiKey | null>;

  public abstract save(tx: Tx, key: AdminApiKey): Promise<AdminApiKey>;

  public abstract listAll(tx: Tx): Promise<ReadonlyArray<AdminApiKey>>;

  /**
   * Mark the key as used. Returns the updated key (with refreshed
   * `lastUsedAt`). The implementation should be idempotent.
   */
  public abstract markUsed(
    tx: Tx,
    id: string,
    when: Date,
  ): Promise<AdminApiKey>;
}

export const ADMIN_API_KEY_REPOSITORY = Symbol('AdminApiKeyRepository');
