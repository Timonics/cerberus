import { createHmac } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../../../config/configuration';

/**
 * HMAC-based lookup-token service for admin API keys.
 *
 * Given a plaintext admin key, computes a deterministic lookup token
 * (HMAC-SHA256 with the server's `lookupSecret`). The token is
 * stored alongside the argon2id hash in the DB; lookup by token is
 * O(1), and only after a successful lookup do we run the slow argon2
 * verification (one verify per request instead of N).
 *
 * Why HMAC and not just `sha256(plaintext)`? An HMAC requires the
 * server-side secret, so an attacker who steals the DB cannot
 * pre-compute a lookup table (unlike with a plain SHA-256). The
 * plaintext-then-HMAC relationship is keyed by the server secret,
 * which an attacker doesn't have.
 *
 * Why hex-encoded output? 64 chars, fixed length, easy to index.
 */
@Injectable()
export class AdminApiKeyLookupTokenService {
  private readonly secret: string;

  public constructor(config: ConfigService) {
    this.secret =
      config.getOrThrow<AppConfig['admin']['lookupSecret']>(
        'admin.lookupSecret',
      );
  }

  /**
   * Compute the deterministic lookup token for a plaintext admin key.
   */
  public compute(plaintext: string): string {
    return createHmac('sha256', this.secret)
      .update(plaintext, 'utf8')
      .digest('hex');
  }
}
