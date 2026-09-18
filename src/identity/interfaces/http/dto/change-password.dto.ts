import { IsString, Length } from 'class-validator';

/** Request body for `POST /v1/identity/change-password`. */
export class ChangePasswordDto {
  @IsString()
  public currentPassword!: string;

  @IsString()
  @Length(12, 128, { message: 'newPassword must be 12–128 characters' })
  public newPassword!: string;
}
