import { Type } from 'class-transformer';
import {
  IsISO8601,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
} from 'class-validator';

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

export class CreateOrganizationDto {
  @IsString()
  @Length(3, 80)
  public slug!: string;

  @IsString()
  @Length(1, 120)
  public name!: string;

  @IsOptional()
  @IsString()
  @Length(0, 500)
  public description?: string;
}

/**
 * Query params for `GET /admin/audit-log`.
 *
 * Audit 2026-10-19: `from`/`to` are validated as strict ISO-8601 here so
 * garbage never reaches `new Date(...)` (which used to produce an
 * Invalid Date that surfaced as a 500 instead of a 400). `limit` /
 * `offset` are coerced to integers and range-checked; the domain
 * value-object re-checks the bounds, so the caps here and there must
 * stay in sync ([1, 500] and [0, 10_000]).
 */
export class AdminAuditLogSearchQueryDto {
  @IsOptional()
  @IsString()
  @Length(0, 64)
  public userId?: string;

  @IsOptional()
  @IsString()
  @Length(0, 120)
  public eventType?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(500)
  public limit?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(10_000)
  public offset?: number;

  @IsOptional()
  @IsISO8601(
    { strict: true },
    { message: '`from` must be a valid ISO-8601 timestamp' },
  )
  public from?: string;

  @IsOptional()
  @IsISO8601(
    { strict: true },
    { message: '`to` must be a valid ISO-8601 timestamp' },
  )
  public to?: string;
}
