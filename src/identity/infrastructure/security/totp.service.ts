import { Injectable } from '@nestjs/common';
import { authenticator } from 'otplib';
import { customAlphabet } from 'nanoid';
import { RedisService } from '../../../redis/redis.service';

/**
 * TOTP secret generator + verifier.
 *
 * Wraps the `otplib` library so the domain layer never imports it
 * directly. Generates RFC 6238 TOTP secrets using base32 encoding
 * (the standard that authenticator apps like Google Authenticator and
 * Authy expect).
 *
 * Defaults (verified against the compiled otplib presets):
 *
 *   * 20-byte secrets (~160 bits of entropy).
 *   * 30-second time step.
 *   * window 0 — ONLY the current time step is accepted. There is no
 *     ±1-step tolerance: a code from the previous or next step is
 *     rejected. This is stricter than the old (incorrect) docs claimed
 *     and means a user whose phone clock is off by >~15s cannot
 *     authenticate. Clock skew tolerance is deliberately NOT widened
 *     here — do it with an explicit `window` option after weighing the
 *     replay-vs-UX trade-off.
 *
 * Replay protection: RFC 6238 §5.2 requires that a code already used
 * for authentication not be accepted again within its validity window.
 * `authenticator.check` does NOT do this (the old comment claiming it
 * did was wrong). `verifyTotpFresh` adds it via a Redis SETNX keyed on
 * (userId, time step) with a 90s TTL: the first verification of a step
 * wins; any later attempt with a code from the same step is rejected.
 */
@Injectable()
export class TotpService {
  /** Validity of a consumed-step marker: 90s covers the 30s step plus
   *  skew headroom without holding the lock longer than needed. */
  private static readonly USED_STEP_TTL_SECONDS = 90;
  private static readonly STEP_SECONDS = 30;

  public constructor(private readonly redis: RedisService) {}

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
   * Verify a 6-digit TOTP code against a secret. Window 0 — only the
   * current time step is accepted (see the class doc).
   *
   * This is a CRYPTOGRAPHIC check only: it does NOT provide RFC 6238
   * §5.2 replay protection. Use `verifyTotpFresh` on every
   * authentication path (mfa/verify, disable-mfa); keep this method
   * for enrollment-style checks where replay is harmless (e.g.
   * confirming enrollment — a second confirm throws
   * `identity.mfa.already_enabled` anyway).
   */
  public verifyTotp(secret: string, code: string): boolean {
    try {
      return authenticator.check(code, secret);
    } catch {
      return false;
    }
  }

  /**
   * Verify a code AND claim the time step so the same step cannot be
   * replayed within its validity window (RFC 6238 §5.2).
   *
   * Algorithm:
   *   1. Cryptographic check (window 0).
   *   2. SETNX `mfa:used:{userId}:{timeStep}` with a 90s TTL. If the
   *      key already exists, this step was consumed — reject.
   *
   * Two presentations of the same code, or of different codes valid
   * in the same step, both land on the same key — only the first
   * succeeds. A legit user verifying two different sessions within one
   * 30s window would be rejected on the second; that is the accepted
   * cost of anti-replay (same trade-off as RFC 6238 prescribes).
   */
  public async verifyTotpFresh(
    userId: string,
    secret: string,
    code: string,
  ): Promise<boolean> {
    if (!this.verifyTotp(secret, code)) {
      return false;
    }
    const step = Math.floor(Date.now() / 1000 / TotpService.STEP_SECONDS);
    const key = `mfa:used:${userId}:${step}`;
    const acquired = await this.redis
      .getClient()
      .set(key, '1', 'EX', TotpService.USED_STEP_TTL_SECONDS, 'NX');
    return acquired === 'OK';
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
