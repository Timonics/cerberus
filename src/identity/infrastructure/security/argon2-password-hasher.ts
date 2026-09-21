import { Injectable, Logger } from '@nestjs/common';
import * as argon2 from 'argon2';
import { PasswordHasher } from '../../../shared/domain/value-objects/password-hash';

/**
 * Argon2id password hasher.
 *
 * Parameters follow OWASP's 2024 minimum recommendations for
 * argon2id, with some headroom for production cost:
 *
 *   * memoryCost: 64 MiB (`m=65536`). OWASP minimum is 19 MiB;
 *     production deployments should target 250–500ms per hash, which
 *     a single-threaded 64 MiB / 3-iteration argon2 verify hits on
 *     modern server hardware. Bump via env var if your hardware is
 *     slower (TODO V1.5: surface these as configurable).
 *   * timeCost: 3 iterations.
 *   * parallelism: 1 (single-threaded).
 *
 * Output is the standard `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`
 * format which is self-describing — stored hashes carry their own
 * parameters, so future increases in memoryCost don't invalidate
 * existing hashes (argon2 reads the parameters from the hash itself).
 */
@Injectable()
export class Argon2PasswordHasher implements PasswordHasher {
  private readonly logger = new Logger(Argon2PasswordHasher.name);
  private readonly options: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: 65_536, // 64 MiB
    timeCost: 3,
    parallelism: 1,
  };

  public async hash(plaintext: string): Promise<string> {
    return argon2.hash(plaintext, this.options);
  }

  public async verify(plaintext: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plaintext);
    } catch (err) {
      // V1.5 (audit M4): log the underlying argon2 error so operators
      // can spot a corrupted hash table. We still return `false` so
      // the user gets the standard "wrong password" UX — the operator
      // sees the real cause in the server logs.
      //
      // Common causes:
      //   * Hash truncated or corrupted (DB migration issue).
      //   * Hash uses unsupported parameters (older argon2 build).
      //   * argon2 native binding failed to load (missing libargon2).
      //
      // We deliberately do NOT throw — throwing would change the
      // 5xx surface and break login UX for valid users with a few
      // bad rows. The log is the right channel for this.
      this.logger.error(
        `Argon2 verify failed (hash prefix ${hash.substring(0, 16)}...): ${(err as Error).message}`,
      );
      return false;
    }
  }
}
