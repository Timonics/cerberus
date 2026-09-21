import {
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { RotateSigningKeyUseCase } from '../../../authorization/application/use-cases/rotate-signing-key.use-case';
import { AdminApiKeyGuard } from '../security/admin-api-key.guard';
import { IpAllowlistGuard } from '../security/ip-allowlist.guard';

/**
 * Operator endpoint to rotate the JWT signing key.
 *
 * V1.5: moved to the admin listener (port 3001) behind
 * `AdminApiKeyGuard` + `IpAllowlistGuard`. Previously this endpoint
 * was on the public listener with NO auth — anyone with network
 * access could rotate the key. That was a critical vulnerability
 * (see audit C1).
 *
 * Idempotent — calling twice within a minute returns the existing
 * current key. The use-case logs the rotation event.
 */
@Controller('admin/keys')
@UseGuards(IpAllowlistGuard, AdminApiKeyGuard)
export class OAuthAdminController {
  public constructor(
    private readonly rotateSigningKeyUc: RotateSigningKeyUseCase,
  ) {}

  @Post('rotate')
  @HttpCode(HttpStatus.OK)
  public async rotate() {
    const result = await this.rotateSigningKeyUc.execute();
    return {
      kid: result.newKey.kid,
      retiredKeyId: result.retiredKeyId,
    };
  }
}
