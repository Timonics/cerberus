import {
  IsEmail,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
} from 'class-validator';

export class RegisterAppDto {
  @IsString()
  @Length(3, 80)
  public name!: string;

  @IsOptional()
  @IsString()
  @Length(0, 500)
  public description?: string;

  /**
   * Slug of the Organization that users registered through this app
   * will be auto-bound to. Optional — apps without a binding still
   * work but users fall through to email-domain / personal-org
   * resolution on register.
   */
  @IsOptional()
  @IsString()
  @Length(3, 80)
  public defaultOrgSlug?: string;

  @IsEmail()
  @Length(3, 255)
  public contactEmail!: string;

  @IsOptional()
  @IsString()
  @Length(0, 500)
  public notes?: string;

  @IsInt()
  @Min(60) // 1 minute minimum
  @Max(60 * 60 * 24 * 365) // 1 year maximum
  public ttlSeconds!: number;
}

export class RotateAppApiKeyDto {
  @IsInt()
  @Min(60)
  @Max(60 * 60 * 24 * 365)
  public ttlSeconds!: number;
}
