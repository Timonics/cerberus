import { IsString, Length } from 'class-validator';

/** Request body for `POST /v1/auth/refresh` and `/logout`. */
export class RefreshTokenDto {
  @IsString()
  @Length(20, 256, { message: 'refreshToken must be 20–256 characters' })
  public refreshToken!: string;
}
