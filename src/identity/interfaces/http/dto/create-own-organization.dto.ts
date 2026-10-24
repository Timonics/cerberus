import { IsOptional, IsString, Length } from 'class-validator';

export class CreateOwnOrganizationDto {
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
