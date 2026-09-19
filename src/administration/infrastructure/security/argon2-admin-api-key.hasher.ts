import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

/**
 * argon2id wrapper for admin API keys.
 *
 * Reuses the OWASP 2024 parameters already in `Argon2PasswordHasher`
 * for user passwords. Stored encoding fits in the `VARCHAR(255)`
 * column.
 */
@Injectable()
export class AdminApiKeyHasher {
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

export const ADMIN_API_KEY_HASHER = Symbol('AdminApiKeyHasher');
