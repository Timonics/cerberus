import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { RegisterAppDto, RotateAppApiKeyDto } from './dto/apps.dto';
import { RegisterAppUseCase } from '../../application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from '../../application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from '../../application/use-cases/revoke-app.use-case';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { VerifyAppApiKeyUseCase } from '../../application/use-cases/verify-app-api-key.use-case';
import { ProductionAdminGuard } from '../../../common/security/production-admin.guard';

/**
 * App registration + key-rotation endpoints.
 *
 * V1.5 (audit C2) hardening:
 *   * `register` (POST /v1/apps) — `@Public` in dev/staging so
 *     an operator can spin up an app without first minting an
 *     admin key. V1.7: behind `ProductionAdminGuard` which
 *     requires a valid admin `Authorization: Bearer *** header
 *     in `NODE_ENV=production` (or always, when
 *     `REQUIRE_ADMIN_FOR_REGISTRATION=true`). The guard's
 *     `domainErrorFilter` mapping turns a missing header into
 *     `admin.auth.missing` → 401.
 *   * `rotateKey` (PATCH /v1/apps/:id/rotate-key) — now requires the
 *     app's CURRENT valid X-Cerberus-App-Id + X-Cerberus-App-Secret
 *     headers, and the `:id` URL param must match the X-Cerberus-App-Id.
 *     Previously anyone who knew an app uuid could rotate its key.
 *   * `revoke` (DELETE /v1/apps/:id) — same auth as rotate-key. The
 *     legitimate app revokes itself; admins have a separate path
 *     through `/admin/api-keys` if needed (V2).
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
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
  ) {}

  /**
   * Verify the caller's current app credentials before allowing a
   * rotate-key or revoke operation. Throws `ForbiddenException` if the
   * path id doesn't match the supplied `X-Cerberus-App-Id` header.
   */
  private async requireOwnCurrentKey(
    urlAppId: string,
    headerAppId: string | undefined,
    headerAppSecret: string | undefined,
  ): Promise<void> {
    if (!headerAppId || !headerAppSecret) {
      throw new ForbiddenException(
        'X-Cerberus-App-Id and X-Cerberus-App-Secret headers required',
      );
    }
    if (urlAppId !== headerAppId) {
      throw new ForbiddenException(
        'App ID in URL does not match X-Cerberus-App-Id header',
      );
    }
    const verified = await this.verifyAppApiKeyUc.execute({
      appId: headerAppId.trim(),
      plaintextApiKey: headerAppSecret.trim(),
    });
    if (!verified || verified.appId !== urlAppId) {
      throw new ForbiddenException('Invalid current app credentials');
    }
  }

  @Public()
  @UseGuards(ProductionAdminGuard)
  @Post()
  @HttpCode(HttpStatus.CREATED)
  public async register(
    @Body() body: RegisterAppDto,
    @Headers('idempotency-key') idempotencyKey?: string,
  ) {
    const { app, plaintextApiKey } = await this.registerAppUc.execute({
      name: body.name,
      description: body.description,
      defaultOrgSlug: body.defaultOrgSlug,
      contactEmail: body.contactEmail,
      notes: body.notes,
      ttlSeconds: body.ttlSeconds,
      initialScopes: body.initialScopes,
      idempotencyKey,
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
        allowedScopes: app.allowedScopes,
      },
      // NULL on an idempotent replay (same Idempotency-Key seen
      // before) — the key plaintext was only returned by the
      // original 201. `idempotentReplay` lets clients distinguish
      // "replay" from "key lost".
      apiKey: plaintextApiKey,
      idempotentReplay: plaintextApiKey === null,
    };
  }

  // V1.5 (audit C2): require current app credentials. Only the app
  // itself can rotate its own key.
  @Patch(':id/rotate-key')
  @HttpCode(HttpStatus.OK)
  public async rotateKey(
    @Param('id') id: string,
    @Body() body: RotateAppApiKeyDto,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
  ) {
    await this.requireOwnCurrentKey(id, appId, appSecret);
    const { app, plaintextApiKey } = await this.rotateKeyUc.execute(
      id,
      body.ttlSeconds,
    );
    return {
      appId: app.id,
      apiKey: plaintextApiKey,
    };
  }

  // V1.5 (audit C2): require current app credentials. Only the app
  // itself can revoke itself. Admin revoke uses a different path.
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async revoke(
    @Param('id') id: string,
    @Headers('x-cerberus-app-id') appId?: string,
    @Headers('x-cerberus-app-secret') appSecret?: string,
  ): Promise<void> {
    await this.requireOwnCurrentKey(id, appId, appSecret);
    await this.revokeAppUc.execute(id);
  }
}
