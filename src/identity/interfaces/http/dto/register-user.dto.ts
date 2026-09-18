import {
  IsEmail,
  IsOptional,
  IsString,
  Length,
  Matches,
} from 'class-validator';

/**
 * Request body for `POST /v1/identity/register`.
 *
 * V1 supports three registration shapes:
 *
 *   1. **Public form (default).** Just `email` + `password`. The auth
 *      service extracts the email domain:
 *        a. If a domain row exists in `organization_domains`, the user
 *           joins that organization automatically.
 *        b. Otherwise, a new "personal" organization is auto-created.
 *
 *   2. **Org-scoped.** Include `organizationSlug`. The user joins that
 *      existing org. Used by consumer apps that embed the org slug as a
 *      hidden form field.
 *
 *   3. **Invite-redeem (V1.5).** `POST /v1/invitations/accept` with a
 *      token — handled by a separate endpoint.
 *
 * `displayName` is always optional.
 *
 * `password` is 12–128 chars (composition + breach-list checks happen in
 * the domain layer; the length cap is the same on both sides for safety).
 */
export class RegisterUserDto {
  @IsEmail({}, { message: 'email must be a valid email address' })
  public email!: string;

  @IsString()
  @Length(12, 128, { message: 'password must be 12–128 characters' })
  public password!: string;

  /**
   * Optional. URL-safe identifier of the Organization the user is joining.
   * If omitted, the auth service picks the org from the email domain
   * (if registered) or creates a personal org.
   */
  @IsOptional()
  @IsString()
  @Matches(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, {
    message:
      'organizationSlug must be lowercase letters/digits/hyphens, no leading/trailing hyphen',
  })
  @Length(3, 63, { message: 'organizationSlug must be 3–63 characters' })
  public organizationSlug?: string;

  @IsOptional()
  @IsString()
  @Length(1, 120, { message: 'displayName must be ≤120 characters' })
  public displayName?: string;
}
