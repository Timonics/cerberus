import { IsInt, IsOptional, IsString, Length, Max, Min } from 'class-validator';

export class IssueAdminApiKeyDto {
  @IsString()
  @Length(3, 80)
  public name!: string;

  @IsString()
  @Length(3, 120)
  public createdBy!: string;

  @IsInt()
  @Min(60) // 1 minute minimum
  @Max(60 * 60 * 24 * 365) // 1 year maximum
  public ttlSeconds!: number;

  @IsOptional()
  @IsString()
  @Length(0, 255)
  public notes?: string;
}

export class ListAdminApiKeysQueryDto {
  @IsOptional()
  @IsString()
  @Length(0, 80)
  public status?: 'active' | 'revoked' | 'all';
}

export class AdminDisableUserMfaDto {
  @IsString()
  @Length(3, 500)
  public reason!: string;
}
