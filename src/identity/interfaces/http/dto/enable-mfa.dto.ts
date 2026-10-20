import { IsString, MinLength } from 'class-validator';

/**
 * Request body for `POST /v1/identity/mfa/enable`.
 *
 * 2026-10-19 audit MEDIUM (MFA enrollment fresh-auth): starting MFA
 * enrollment previously required only a bearer token. A stolen token
 * could then enable MFA and lock the legitimate user out persistently.
 * The current password is now required, verified against the
 * credential hash with dummy-verify timing equalization.
 */
export class EnableMfaDto {
  @IsString()
  @MinLength(1, { message: 'currentPassword must not be empty' })
  public currentPassword!: string;
}
