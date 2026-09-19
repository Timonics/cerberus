import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

/**
 * argon2id wrapper for App API keys.
 *
 * Reuses the OWASP 2024 parameters already in `Argon2PasswordHasher`
 * and `Argon2AdminApiKeyHasher`. The encoded `$argon2id$v=19$...`
 * string fits in the `VARCHAR(255)` column.
 */
@Injectable()
export class Argon2AppApiKeyHasher {
  private readonly options = {
    type: 2 as const, // argon2id
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  };

  public async hash(plaintext: string): Promise<string> {
    return argon2.hash(plaintext, this.options);
  }

  public async verify(hashStr: string, plaintext: string): Promise<boolean> {
    try {
      return await argon2.verify(hashStr, plaintext);
    } catch {
      return false;
    }
  }
}

export const APP_API_KEY_HASHER = Symbol('Argon2AppApiKeyHasher');
