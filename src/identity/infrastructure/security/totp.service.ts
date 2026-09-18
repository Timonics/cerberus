import { Injectable } from '@nestjs/common';
import { authenticator } from 'otplib';
import { customAlphabet } from 'nanoid';

/**
 * TOTP secret generator + verifier.
 *
 * Wraps the `otplib` library so the domain layer never imports it
 * directly. Generates RFC 6238 TOTP secrets using base32 encoding
 * (the standard that authenticator apps like Google Authenticator and
 * Authy expect).
 *
 * Defaults:
 *
 *   * 20-byte secrets (~160 bits of entropy).
 *   * 30-second time step.
 *   * 1-step window for verification (±30s tolerance, so a user whose
 *     phone clock is slightly off can still authenticate).
 *
 * The `verifyTotp` method accepts the same tolerance — domain code
 * never knows these specifics.
 */
@Injectable()
export class TotpService {
  /** Generate a fresh base32-encoded TOTP secret. */
  public generateSecret(): string {
    // 20 bytes = 160 bits, base32-encoded to 32 characters.
    return authenticator.generateSecret(20);
  }

  /**
   * Build an otpauth:// URI for QR code generation. The user's
   * authenticator app scans this to enroll. We do not include the QR
   * image generation here — that's the HTTP layer's job (uses a
   * client-side library; no server-side dependency needed).
   */
  public buildOtpAuthUrl(params: {
    secret: string;
    accountName: string; // typically the user's email
    issuer: string; // typically the org slug or "Cerberus"
  }): string {
    return authenticator.keyuri(
      params.accountName,
      params.issuer,
      params.secret,
    );
  }

  /**
   * Verify a 6-digit TOTP code against a secret. Returns true if the
   * code is valid within the configured time window (±1 step).
   *
   * The `authenticator.check` method already handles constant-time
   * comparison and replay protection (per RFC 6238 §5.2).
   */
  public verifyTotp(secret: string, code: string): boolean {
    try {
      return authenticator.check(code, secret);
    } catch {
      return false;
    }
  }

  /**
   * Recovery code generator.
   *
   * Produces 10-character codes using a Crockford-base32 alphabet (no
   * easily-confused characters like 0/O/1/I/L). 10 characters at
   * Crockford-base32 gives ~50 bits of entropy per code — sufficient
   * since each code is single-use.
   *
   * Exposed here rather than in a separate class because the
   * `MfaSecret` aggregate needs both TOTP secret generation and
   * recovery code generation in one transaction (EnableMfaUseCase),
   * and they're conceptually a single "authenticator enrollment"
   * capability.
   */
  public generateRecoveryCodes(count = 10): string[] {
    const generator = customAlphabet(
      '0123456789ABCDEFGHJKMNPQRSTVWXYZ', // Crockford base32 (no I, L, O, U)
      10,
    );
    return Array.from({ length: count }, () => generator());
  }
}
