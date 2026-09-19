import { IsIn, IsOptional, IsString } from 'class-validator';

/** RFC 7662 introspect + RFC 7009 revoke request body. */
export class TokenInspectDto {
  @IsString()
  public token!: string;

  @IsOptional()
  @IsIn(['access_token', 'refresh_token'])
  public token_type_hint?: 'access_token' | 'refresh_token';
}
