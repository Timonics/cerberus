import {
  IsEmail,
  IsOptional,
  IsString,
  Length,
  Matches,
} from 'class-validator';

/**
 * Request body for `POST /v1/auth/login`.
 */
export class LoginDto {
  @IsEmail({}, { message: 'email must be a valid email address' })
  public email!: string;

  @IsString()
  @Length(12, 128, { message: 'password must be 12–128 characters' })
  public password!: string;

  /** Optional. The user's User-Agent string for the session record. */
  @IsOptional()
  @IsString()
  @Length(1, 1024)
  public userAgent?: string;

  /**
   * Optional. The IP address for the session record + lockout keying.
   * In practice this comes from the request (we use the upstream proxy's
   * `X-Forwarded-For` if present, else the socket peer).
   */
  @IsOptional()
  @IsString()
  @Matches(/^[0-9a-fA-F.:]+$/, {
    message: 'ipAddress contains invalid characters',
  })
  @Length(1, 64)
  public ipAddress?: string;
}
