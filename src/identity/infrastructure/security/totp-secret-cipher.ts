import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { AppConfig } from '../../../config/configuration';

/**
 * AES-256-GCM cipher for TOTP secrets at rest (audit H-5a).
 *
 * `MfaSecret.secret` used to be stored as plaintext base32 — a DB dump
 * yielded every user's live TOTP key. This cipher encrypts the secret
 * with a boot-required master key (`MFA_SECRET_KEY`) before it reaches
 * the repository, and decrypts on load.
 *
 * Wire format: `v1:<base64 iv>:<base64 authTag>:<base64 ciphertext>`.
 *
 * The `v1:` prefix gives us a version byte for free, so a future
 * algorithm/migration can distinguish formats without a schema change.
 * Rows written before this fix are raw base32 plaintext; `decrypt`
 * passes those through unchanged so existing enrollments keep working
 * (they are re-encrypted on the next `save`).
 *
 * Key handling: the key is loaded once at construction. The first 32
 * bytes of the env value are used directly as the AES-256 key, so
 * operators should supply 32+ chars of entropy (Joi enforces the
 * minimum and rejects the dev default in production).
 */
@Injectable()
export class TotpSecretCipher {
  private readonly key: Buffer;

  public constructor(config: ConfigService) {
    const raw = config.getOrThrow<AppConfig['mfaSecretKey']>('mfaSecretKey');
    // AES-256 wants exactly 32 bytes. The env contract guarantees
    // >= 32 chars; fold longer values down deterministically.
    this.key = Buffer.from(raw, 'utf8').subarray(0, 32);
  }

  public encrypt(plaintext: string): string {
    const iv = randomBytes(12); // 96-bit IV — the GCM-recommended size
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
  }

  /**
   * Decrypt a wire-format secret. Legacy plaintext rows (anything not
   * starting with `v1:`) are returned unchanged — see the class doc.
   */
  public decrypt(stored: string): string {
    if (!stored.startsWith('v1:')) {
      return stored;
    }
    const parts = stored.split(':');
    if (parts.length !== 4) {
      throw new Error(
        'Malformed encrypted TOTP secret (expected v1:<iv>:<tag>:<ct>)',
      );
    }
    const [, ivB64, tagB64, ctB64] = parts;
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(ivB64, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const pt = Buffer.concat([
      decipher.update(Buffer.from(ctB64, 'base64')),
      decipher.final(),
    ]);
    return pt.toString('utf8');
  }
}
