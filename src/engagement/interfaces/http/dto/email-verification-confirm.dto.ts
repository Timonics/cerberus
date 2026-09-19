import { IsString, Length } from 'class-validator';

/** Request body for `POST /v1/engagement/email-verification/confirm`. */
export class EmailVerificationConfirmDto {
  @IsString()
  @Length(20, 256, { message: 'token must be 20–256 characters' })
  public token!: string;
}
