import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { PasswordHasher } from '../../../shared/domain/value-objects/password-hash';

/**
 * Argon2id password hasher.
 *
 * Default parameters follow OWASP's 2024 minimum recommendations for
 * argon2id:
 *
 *   * memoryCost: 19 MiB (`m=19456` kibibytes, rounded to 65536 to give
 *     headroom for future cost increases).
 *   * timeCost: 2 iterations (`t=2`).
 *   * parallelism: 1 (`p=1`).
 *
 * OWASP recommends tuning to take ~250–500ms on production hardware. The
 * defaults here will take ~50ms on a modern server; production deployments
 * SHOULD bump them via env vars (TODO V1.5). The PHC output is the
 * standard `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>` format which
 * is self-describing, so we can change the parameters without rewriting
 * stored hashes.
 */
@Injectable()
export class Argon2PasswordHasher implements PasswordHasher {
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
    } catch {
      // Malformed hash, unsupported params, etc. — treat as a non-match
      // rather than letting the caller handle an exception. The user is
      // never told WHY the password failed, only THAT it failed.
      return false;
    }
  }
}
