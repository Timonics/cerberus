import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';

/**
 * Admin-side health endpoint.
 *
 * Lives in its OWN controller (no `@UseGuards(...)`) so it bypasses
 * the IP-allowlist + admin-API-key guards on the protected surface.
 *
 * Load balancers use this for admin-side liveness probes; the public
 * `/health` on port 3000 covers the public app.
 */
@Controller('admin')
export class AdminHealthController {
  @Get('health')
  @HttpCode(HttpStatus.OK)
  public health(): { status: 'ok'; surface: 'admin' } {
    return { status: 'ok', surface: 'admin' };
  }
}
