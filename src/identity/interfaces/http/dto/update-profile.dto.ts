import { IsIn, IsOptional, IsString, Length } from 'class-validator';

/**
 * Request body for `PATCH /v1/identity/me`.
 *
 * V1 supports updating the user's display name. Two valid shapes:
 *
 *   * `{ "displayName": "Alice" }` — set to a new name (1–120 chars).
 *   * `{ "displayName": null, "clearDisplayName": true }` — clear.
 *
 * At least one of `displayName` or `clearDisplayName: true` must be
 * present. The controller rejects empty bodies with 400.
 *
 * Email changes are deferred to V1.5 (they require a re-verification
 * round-trip via the Engagement context).
 */
export class UpdateProfileDto {
  /**
   * New display name. `null` (combined with `clearDisplayName: true`)
   * clears the name. Strings must be 1–120 chars.
   */
  @IsOptional()
  @IsString({ message: 'displayName must be a string' })
  @Length(1, 120, { message: 'displayName must be 1–120 characters' })
  public displayName?: string | null;

  /** Set to true to clear the display name. */
  @IsOptional()
  @IsIn([true], { message: 'clearDisplayName must be true' })
  public clearDisplayName?: boolean;
}
