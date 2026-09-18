import { IsUUID } from 'class-validator';

/** Request body for `POST /v1/auth/sessions/:id/revoke`. */
export class RevokeSessionDto {
  @IsUUID('4', { message: 'sessionId must be a UUID' })
  public sessionId!: string;
}
