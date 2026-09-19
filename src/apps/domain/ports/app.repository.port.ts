import { Tx } from '../../../shared/domain';
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
}

export const APP_REPOSITORY = Symbol('AppRepository');
