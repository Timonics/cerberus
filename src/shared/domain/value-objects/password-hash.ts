import { DomainError } from '../errors/domain-error';

/**
 * Argon2id password hash.
 *
 * This is the value object that wraps the serialized hash produced by the
 * argon2 algorithm. The string format is the standard PHC ("Password Hashing
 * Competition") string: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`.
 *
 * We expose a constructor only — we never *parse* the format ourselves;
 * argon2's verify function does that for us. The purpose of the wrapper is
 * to:
 *
 *   * Mark this string as "already hashed" so it can never accidentally be
 *     passed to a function that hashes again (a real foot-gun in auth code).
 *   * Provide `verify()` that delegates to the injected hasher port — the
 *     domain layer never imports argon2 directly.
 *   * Provide `toString()` for persistence (column type `text` in Postgres).
 */
export class PasswordHash {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /**
   * Construct a hash from an already-serialized PHC string. Used by the
   * repository adapter when rehydrating from the database.
   */
  public static rehydrate(value: string): PasswordHash {
    if (!value.startsWith('$argon2id$')) {
      throw new DomainError(
        'identity.password.too_weak',
        'Stored password hash is not a valid argon2id PHC string',
      );
    }
    return new PasswordHash(value);
  }

  /**
   * Construct from a freshly-produced hash (e.g. just produced by the
   * hasher adapter). Performs the same format check as `rehydrate` so we
   * don't accidentally persist garbage.
   */
  public static fromHashString(value: string): PasswordHash {
    if (!value.startsWith('$argon2id$')) {
      throw new DomainError(
        'identity.password.too_weak',
        'Produced password hash is not a valid argon2id PHC string',
      );
    }
    return new PasswordHash(value);
  }

  /** Persistable form. */
  public toString(): string {
    return this.value;
  }

  public equals(other: PasswordHash): boolean {
    return this.value === other.value;
  }
}

/**
 * Outbound port for password hashing and verification.
 *
 * The argon2 parameters (`memoryKiB`, `iterations`, `parallelism`) are
 * configured at the adapter level, not here. The domain layer must not know
 * about argon2 specifics — only that "I can hash this, I can verify this".
 */
export interface PasswordHasher {
  /**
   * Hash a plaintext password using argon2id with the configured parameters.
   * The returned string is a complete PHC string ready for storage.
   */
  hash(plaintext: string): Promise<string>;

  /**
   * Verify a plaintext password against a stored hash. Returns `true` if the
   * password matches, `false` otherwise. MUST use a constant-time comparison
   * internally (argon2 does this for us; never roll your own).
   */
  verify(plaintext: string, hash: string): Promise<boolean>;
}

export const PASSWORD_HASHER = Symbol('PasswordHasher');
