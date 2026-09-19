import { IsString, Length } from 'class-validator';

/**
 * Request body for `POST /v1/engagement/password-reset/confirm`.
 *
 * Public endpoint. The `token` is the plaintext that was emailed to
 * the user. `newPassword` is the new password (12–128 chars, validated
 * by the domain `Password` value object).
 */
export class PasswordResetConfirmDto {
  @IsString()
  @Length(20, 256, { message: 'token must be 20–256 characters' })
  public token!: string;

  @IsString()
  @Length(12, 128, { message: 'newPassword must be 12–128 characters' })
  public newPassword!: string;
}
