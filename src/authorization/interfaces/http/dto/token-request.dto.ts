import { IsIn, IsOptional, IsString } from 'class-validator';

/**
 * OAuth2 token endpoint request body.
 *
 * V1 supports two grant types:
 *   * `password` — direct email + password. Convenient for first-party
 *     apps; RFC 6749 §4.3 recommends against this for third-party.
 *   * `refresh_token` — exchange a refresh token for a fresh access
 *     token (and optionally a new refresh token).
 *
 * V1.6 adds:
 *   * `client_credentials` — RFC 6749 §4.4. The App's UUID is the
 *     `client_id`, the plaintext key returned at register-time is
 *     the `client_secret`. No refresh_token in the response — apps
 *     re-mint when needed.
 *
 * The endpoint accepts both application/x-www-form-urlencoded and JSON.
 */
export class TokenRequestDto {
  @IsIn(['password', 'refresh_token', 'client_credentials'])
  public grant_type!: 'password' | 'refresh_token' | 'client_credentials';

  // username + password (for grant_type=password)
  @IsOptional()
  @IsString()
  public username?: string;

  @IsOptional()
  @IsString()
  public password?: string;

  // refresh_token (for grant_type=refresh_token)
  @IsOptional()
  @IsString()
  public refresh_token?: string;

  // client_credentials grant (RFC 6749 §4.4)
  /**
   * App UUID. Equivalent to the X-Cerberus-App-Id header that
   * register/login flows use today — same identifier, different
   * transport (form body vs header).
   */
  @IsOptional()
  @IsString()
  public client_id?: string;

  /**
   * Plaintext App API key. Equivalent to the X-Cerberus-App-Secret
   * header. Stored only as argon2id hash on the server side.
   */
  @IsOptional()
  @IsString()
  public client_secret?: string;

  /**
   * Optional scope restriction. Must be a subset of what the app's
   * allowedScopes allowlist permits. V1.6: enforced via the
   * client_credentials grant; ignored on password / refresh_token
   * (the user-bound token is always issued with the full default
   * scope set derived from the user's role).
   */
  @IsOptional()
  @IsString()
  public scope?: string;
}
