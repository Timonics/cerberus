import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { ProvisionServiceDto, GrantServiceDto } from './dto/services-admin.dto';
import { ProvisionServiceUseCase } from '../../../services/application/use-cases/provision-service.use-case';
import { GrantServiceUseCase } from '../../../services/application/use-cases/grant-service.use-case';
import { RevokeServiceUseCase } from '../../../services/application/use-cases/revoke-service.use-case';
import { ListServicesUseCase } from '../../../services/application/use-cases/list-services.use-case';
import { GetOrgServicesUseCase } from '../../../services/application/use-cases/get-org-services.use-case';
import { AdminApiKeyGuard } from '../security/admin-api-key.guard';
import { IpAllowlistGuard } from '../security/ip-allowlist.guard';

interface AdminRequest extends Request {
  adminKey: { adminKeyId: string; role: 'ADMIN' | 'SUPER_ADMIN' };
}

function getAdminKeyId(req: Request): string {
  return (req as AdminRequest).adminKey?.adminKeyId ?? 'unknown';
}

/**
 * Admin surface for the Services bounded context: catalog provisioning
 * and per-organization entitlement grants. Lives on the admin listener
 * (port 3001) behind the same IP allowlist + admin API key guards as
 * the rest of `/admin/*`.
 *
 * Endpoints:
 *   POST /admin/services                 — provision (upsert by slug)
 *   GET  /admin/services                 — list catalog
 *   POST /admin/services/:slug/grant     — grant to an org
 *   POST /admin/services/:slug/revoke    — revoke from an org
 *   GET  /admin/orgs/:slug/services      — list an org's entitlements
 */
@Controller('admin')
@UseGuards(IpAllowlistGuard, AdminApiKeyGuard)
export class ServicesAdminController {
  public constructor(
    private readonly provisionServiceUc: ProvisionServiceUseCase,
    private readonly grantServiceUc: GrantServiceUseCase,
    private readonly revokeServiceUc: RevokeServiceUseCase,
    private readonly listServicesUc: ListServicesUseCase,
    private readonly getOrgServicesUc: GetOrgServicesUseCase,
  ) {}

  @Post('services')
  @HttpCode(HttpStatus.CREATED)
  public async provisionService(
    @Body() body: ProvisionServiceDto,
    @Req() req: Request,
  ) {
    const { service, updated } = await this.provisionServiceUc.execute({
      slug: body.slug,
      name: body.name,
      description: body.description ?? null,
      adminKeyId: getAdminKeyId(req),
    });
    return {
      id: service.id,
      slug: service.slug.value,
      name: service.name,
      description: service.description,
      status: service.status,
      updated,
      createdAt: service.createdAt.toISOString(),
    };
  }

  @Get('services')
  public async listServices() {
    const { services } = await this.listServicesUc.execute();
    return {
      services: services.map((s) => ({
        id: s.id,
        slug: s.slug.value,
        name: s.name,
        description: s.description,
        status: s.status,
        createdAt: s.createdAt.toISOString(),
      })),
    };
  }

  @Post('services/:slug/grant')
  @HttpCode(HttpStatus.OK)
  public async grantService(
    @Param('slug') slug: string,
    @Body() body: GrantServiceDto,
    @Req() req: Request,
  ) {
    const { entitlement, reactivated } = await this.grantServiceUc.execute({
      serviceSlug: slug,
      organizationSlug: body.organizationSlug,
      adminKeyId: getAdminKeyId(req),
    });
    return {
      entitlementId: entitlement.id,
      organizationId: entitlement.organizationId.value,
      serviceId: entitlement.serviceId,
      status: entitlement.status,
      reactivated,
    };
  }

  @Post('services/:slug/revoke')
  @HttpCode(HttpStatus.OK)
  public async revokeService(
    @Param('slug') slug: string,
    @Body() body: GrantServiceDto,
    @Req() req: Request,
  ) {
    const { entitlement, revoked } = await this.revokeServiceUc.execute({
      serviceSlug: slug,
      organizationSlug: body.organizationSlug,
      adminKeyId: getAdminKeyId(req),
    });
    return {
      entitlementId: entitlement.id,
      organizationId: entitlement.organizationId.value,
      serviceId: entitlement.serviceId,
      status: entitlement.status,
      revoked,
    };
  }

  @Get('orgs/:slug/services')
  public async getOrgServices(@Param('slug') slug: string) {
    const { entitlements } = await this.getOrgServicesUc.execute({
      organizationSlug: slug,
    });
    return {
      services: entitlements.map(({ entitlement, service }) => ({
        serviceSlug: service.slug.value,
        serviceName: service.name,
        serviceStatus: service.status,
        entitlementStatus: entitlement.status,
        grantedAt: entitlement.createdAt.toISOString(),
      })),
    };
  }
}
