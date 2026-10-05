import { Clock, Tx } from '../../../shared/domain';
import { App } from '../aggregates/app';

export abstract class AppRepository {
  public abstract findById(tx: Tx, id: string): Promise<App | null>;

  /**
   * Find an app by the hashed app-key. Returns null if no match, if
   * the matched app is revoked, or if the matched key is revoked /
   * expired. The use-case then asks the aggregate + key to verify
   * the token.
   */
  public abstract findActiveByKeyHash(
    tx: Tx,
    keyHash: string,
  ): Promise<App | null>;

  public abstract save(tx: Tx, app: App): Promise<App>;

  /**
   * V1.5: revoke a single AppApiKey row by id (sets `revokedAt = now`).
   * Used by `RotateAppApiKeyUseCase` to invalidate the previous key
   * when a new one is minted — the old key row stays in the DB for
   * audit but can no longer be used to authenticate.
   */
  public abstract revokeKey(tx: Tx, keyId: string, clock: Clock): Promise<void>;
}

export const APP_REPOSITORY = Symbol('AppRepository');
