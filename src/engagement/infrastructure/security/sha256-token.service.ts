import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { AppConfig } from '../../../config/configuration';

/**
 * Token hashing + generation for email-verification and password-reset.
 *
 * V1.5 (audit H1): switched from plain SHA-256 to HMAC-SHA-256 with a
 * server-side secret (`TOKEN_SECRET`). With plain SHA-256, an attacker
 * who steals the DB could pre-compute hashes for known token formats
 * (e.g. all 32-byte base64url strings). HMAC requires the server
 * secret, so the attacker can't pre-compute — they have to crack the
 * server's TOKEN_SECRET first.
 *
 * The plaintext tokens we issue are still 32 bytes of crypto-grade
 * random (256 bits of entropy). With HMAC we add the server secret as
 * a second factor. Even if the entropy is ever reduced (e.g. a
 * "magic-link" 16-byte variant), HMAC keeps it safe as long as the
 * server secret is unknown to the attacker.
 *
 * Format: 64-char lowercase hex (HMAC-SHA-256 output).
 *
 * Renamed: implementation switched from plain SHA-256 to HMAC-SHA-256.
 * File path and class name retained as `Sha256TokenService` for
 * migration ease — DI tokens, imports, and test mocks all keep
 * working. A future rename can drop the SHA-256 from the name.
 */
@Injectable()
export class Sha256TokenService {
  private readonly secret: Buffer;

  public constructor(config: ConfigService) {
    // We load the secret once at construction. If the env var changes
    // mid-process, the process must be restarted to pick up the new
    // value (same as the JWT signing-key behavior).
    this.secret = Buffer.from(
      config.getOrThrow<AppConfig['tokenSecret']>('tokenSecret'),
      'utf8',
    );
  }

  /**
   * Hash a plaintext token. The HMAC keyed by the server secret
   * ensures DB leaks alone can't be used to forge hashes.
   */
  public hash(plaintext: string): string {
    return createHmac('sha256', this.secret)
      .update(plaintext, 'utf8')
      .digest('hex');
  }

  /**
   * Generate a fresh plaintext token. 32 bytes of crypto-grade
   * random, base64url-encoded (43 chars). Single-use; persisted only
   * as the hash.
   */
  public generatePlaintext(): string {
    return randomBytes(32).toString('base64url');
  }

  /**
   * Used by V1 legacy tokens (plain SHA-256 without a secret) to
   * check whether a presented plaintext matches a stored legacy hash.
   *
   * V1.5 still supports this for the duration of one token TTL
   * (24 hours for email-verification, 1 hour for password-reset).
   * After that window, all legacy tokens have expired and this
   * method can be deleted.
   *
   * Why not just remove V1 hashes? Because the DB might have rows
   * created before this migration ran. Confirming an outstanding
   * token with a SHA-256 fallback lets users complete their flow
   * during the migration window without forcing a re-issue.
   *
   * @internal visible to legacy support code only
   */
  public legacySha256(plaintext: string): string {
    return createHash('sha256').update(plaintext, 'utf8').digest('hex');
  }
}
