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
 * The endpoint accepts both application/x-www-form-urlencoded and JSON.
 */
export class TokenRequestDto {
  @IsIn(['password', 'refresh_token'])
  public grant_type!: 'password' | 'refresh_token';

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

  /**
   * Optional scope restriction. Must be a subset of what the user
   * (or refresh-token-bound session) is allowed. V1: ignored — we
   * issue the full default scope set.
   */
  @IsOptional()
  @IsString()
  public scope?: string;
}
