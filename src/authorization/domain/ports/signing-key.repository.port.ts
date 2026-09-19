import { Tx } from '../../../shared/domain';
import { SigningKey } from '../aggregates/signing-key';

/**
 * Repository for signing keys.
 *
 * The repository is intentionally NOT a `BaseRepository` subclass —
 * `BaseRepository` is keyed by aggregate ID, but signing keys are
 * primarily accessed by `kid` (the public identifier in JWT headers)
 * or by `isCurrent = true`. We define the operations directly.
 */
export abstract class SigningKeyRepository {
  /** Return the one current key. Throws if there is none. */
  public abstract getCurrent(tx: Tx): Promise<SigningKey>;

  /** Return the key with the given `kid`, or null. */
  public abstract findByKid(tx: Tx, kid: string): Promise<SigningKey | null>;

  /** Return all keys that can verify tokens at the given time. */
  public abstract findVerifyingAt(
    tx: Tx,
    when: Date,
  ): Promise<ReadonlyArray<SigningKey>>;

  /** Persist a new key (typically called with `isCurrent = true`). */
  public abstract save(tx: Tx, key: SigningKey): Promise<SigningKey>;

  /**
   * Atomically: mark `key` as not-current, then mark `newCurrent` as current.
   * Both rows update in a single SQL UPDATE.
   */
  public abstract rotate(
    tx: Tx,
    retiredKeyId: string,
    newCurrentKey: SigningKey,
  ): Promise<SigningKey>;
}

export const SIGNING_KEY_REPOSITORY = Symbol('SigningKeyRepository');
