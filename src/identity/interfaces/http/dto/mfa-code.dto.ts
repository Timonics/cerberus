import { IsString, IsUUID, Matches } from 'class-validator';

/**
 * Request body for the second-factor verification endpoint.
 *
 * Accepts either:
 *   * a 6-digit TOTP code (RFC 6238)
 *   * a 10-character Crockford-base32 recovery code
 *
 * The use-case routes the code to the right verifier based on its shape.
 *
 * V1.5 (audit C-4): requires the `sessionId` of the session to mark
 * MFA-verified. The sessionId is returned from the login response when
 * MFA is required.
 */
export class MfaCodeDto {
  @IsUUID('4', { message: 'sessionId must be a UUID' })
  public sessionId!: string;

  @IsString()
  @Matches(/^(\d{6}|[0-9A-Z]{10})$/i, {
    message: 'code must be a 6-digit TOTP code or a 10-character recovery code',
  })
  public code!: string;
}
