import { IsEmail, IsOptional, IsString, Length } from 'class-validator';

/**
 * Request body for `POST /v1/auth/login`.
 *
 * V1.5 (audit M3): removed the user-controlled `ipAddress` field.
 * Previously a client could send `{"ipAddress": "0.0.0.0"}` in the
 * body, which the use-case used to key the lockout window — letting
 * an attacker bypass per-IP lockout by claiming every request came
 * from a single IP. The controller now uses the server-derived
 * `@Ip()` decorator (which honors `app.set('trust proxy', ...)`).
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
   * Optional inline second factor (2026-10-19 audit fix C1). When the
   * user has MFA enabled and supplies a valid 6-digit TOTP code here,
   * the login completes in one round-trip with the normal token
   * response. Without it — or with an invalid code — the response is
   * `{ mfaRequired: true, mfaToken, sessionId }` and no tokens are
   * issued until POST /v1/identity/mfa/verify completes.
   */
  @IsOptional()
  @IsString()
  @Length(6, 6, { message: 'mfaCode must be a 6-digit TOTP code' })
  public mfaCode?: string;
}
