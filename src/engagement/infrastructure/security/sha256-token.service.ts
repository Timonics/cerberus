import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';

/**
 * SHA-256 token hashing + generation.
 *
 * `hash()` produces a 64-char lowercase hex string. Used by the
 * email-verification and password-reset use-cases to store token
 * fingerprints (the plaintext token is sent to the user via email;
 * only the hash is persisted).
 *
 * `generatePlaintext()` returns a 32-byte base64url-encoded random
 * string. 256 bits of entropy is far more than sufficient for these
 * single-use tokens.
 *
 * Why not JWT or some other structured token? Because we want the
 * token to be opaque — the user can't reverse-engineer claims from it.
 * SHA-256 + base64url gives us that with minimal code.
 */
@Injectable()
export class Sha256TokenService {
  public hash(plaintext: string): string {
    return createHash('sha256').update(plaintext, 'utf8').digest('hex');
  }

  public generatePlaintext(): string {
    return randomBytes(32).toString('base64url');
  }
}
