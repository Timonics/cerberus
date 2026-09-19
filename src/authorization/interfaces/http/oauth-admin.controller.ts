import { Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { RotateSigningKeyUseCase } from '../../application/use-cases/rotate-signing-key.use-case';

/**
 * Operator endpoint to rotate the signing key.
 *
 * V1: no auth on this endpoint. Production deployments MUST restrict
 * it at the network layer (admin-only VPN, internal management port).
 * The Administration context (Phase 15) adds API-key auth here.
 *
 * Idempotent — calling twice within a minute returns the existing
 * current key. The use-case logs the rotation event.
 */
@Controller('oauth/admin')
export class OAuthAdminController {
  public constructor(
    private readonly rotateSigningKeyUc: RotateSigningKeyUseCase,
  ) {}

  @Post('keys/rotate')
  @HttpCode(HttpStatus.OK)
  public async rotate() {
    const result = await this.rotateSigningKeyUc.execute();
    return {
      kid: result.newKey.kid,
      retiredKeyId: result.retiredKeyId,
    };
  }
}
