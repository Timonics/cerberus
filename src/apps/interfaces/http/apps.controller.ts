import {
  Body,
  Controller,
  Delete,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { RegisterAppDto, RotateAppApiKeyDto } from './dto/apps.dto';
import { RegisterAppUseCase } from '../../application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from '../../application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from '../../application/use-cases/revoke-app.use-case';

/**
 * App registration + key-rotation endpoints (public surface).
 *
 * V1 has no GET list endpoint — apps fetch their own details by
 * storing the app id returned from `POST /v1/apps`. V1.5 will add
 * a `GET /v1/apps/:id` that's gated by the app's own current key.
 */
@Controller('apps')
export class AppsController {
  public constructor(
    private readonly registerAppUc: RegisterAppUseCase,
    private readonly rotateKeyUc: RotateAppApiKeyUseCase,
    private readonly revokeAppUc: RevokeAppUseCase,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  public async register(@Body() body: RegisterAppDto) {
    const { app, plaintextApiKey } = await this.registerAppUc.execute({
      name: body.name,
      description: body.description,
      defaultOrgSlug: body.defaultOrgSlug,
      contactEmail: body.contactEmail,
      notes: body.notes,
      ttlSeconds: body.ttlSeconds,
    });
    return {
      app: {
        id: app.id,
        name: app.name,
        description: app.description,
        defaultOrgSlug: app.defaultOrgSlug,
        contactEmail: app.contactEmail,
        createdAt: app.createdAt.toISOString(),
        notes: app.notes,
      },
      // Plaintext returned ONCE — never retrievable again.
      apiKey: plaintextApiKey,
    };
  }

  @Patch(':id/rotate-key')
  @HttpCode(HttpStatus.OK)
  public async rotateKey(
    @Param('id') id: string,
    @Body() body: RotateAppApiKeyDto,
  ) {
    const { app, plaintextApiKey } = await this.rotateKeyUc.execute(
      id,
      body.ttlSeconds,
    );
    return {
      appId: app.id,
      apiKey: plaintextApiKey,
    };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async revoke(@Param('id') id: string): Promise<void> {
    await this.revokeAppUc.execute(id);
  }
}
