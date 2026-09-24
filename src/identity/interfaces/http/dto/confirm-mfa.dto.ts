import { IsString, Matches } from 'class-validator';

/**
 * Request body for `POST /v1/identity/mfa/confirm` — the FIRST-TIME
 * confirmation of an MFA enrollment.
 *
 * Differs from `MfaCodeDto` in that it does NOT require a sessionId:
 * the user is verifying their just-enrolled TOTP code against the
 * pending MfaSecret row, not against an existing session. The DTO
 * was historically shared with `mfa/verify` but they have different
 * semantics — see `MfaCodeDto` for the verify path.
 *
 * Accepts either:
 *   * a 6-digit TOTP code (RFC 6238)
 *   * a 10-character Crockford-base32 recovery code
 *
 * The use-case routes the code to the right verifier based on its shape.
 */
export class ConfirmMfaDto {
  @IsString()
  @Matches(/^(\d{6}|[0-9A-Z]{10})$/i, {
    message: 'code must be a 6-digit TOTP code or a 10-character recovery code',
  })
  public code!: string;
}
