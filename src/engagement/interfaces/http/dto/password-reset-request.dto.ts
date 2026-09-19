import { IsEmail } from 'class-validator';

/**
 * Request body for `POST /v1/engagement/password-reset/request`.
 *
 * Public endpoint — anyone with an email address can request a reset
 * (the response is the same regardless of whether the user exists).
 */
export class PasswordResetRequestDto {
  @IsEmail({}, { message: 'email must be a valid email address' })
  public email!: string;
}
