import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AdminDisableUserMfaDto, IssueAdminApiKeyDto } from './dto/admin.dto';
import { IssueAdminApiKeyUseCase } from '../../application/use-cases/issue-admin-api-key.use-case';
import { RevokeAdminApiKeyUseCase } from '../../application/use-cases/revoke-admin-api-key.use-case';
import { AdminDisableUserMfaUseCase } from '../../application/use-cases/admin-disable-user-mfa.use-case';
import { AdminSearchAuditLogUseCase } from '../../application/use-cases/admin-search-audit-log.use-case';
import { AdminApiKeyGuard } from '../security/admin-api-key.guard';
import { IpAllowlistGuard } from '../security/ip-allowlist.guard';
import { GetUserUseCase } from '../../../identity/application/use-cases/get-user.use-case';

interface AdminRequest extends Request {
  adminKey: { adminKeyId: string; role: 'ADMIN' | 'SUPER_ADMIN' };
}

function getAdminKeyId(req: Request): string {
  return (req as AdminRequest).adminKey?.adminKeyId ?? 'unknown';
}

@Controller('admin')
@UseGuards(IpAllowlistGuard, AdminApiKeyGuard)
export class AdminController {
  public constructor(
    private readonly issueKeyUc: IssueAdminApiKeyUseCase,
    private readonly revokeKeyUc: RevokeAdminApiKeyUseCase,
    private readonly adminDisableMfaUc: AdminDisableUserMfaUseCase,
    private readonly adminSearchAuditLogUc: AdminSearchAuditLogUseCase,
    private readonly getUserUc: GetUserUseCase,
  ) {}

  @Post('api-keys')
  @HttpCode(HttpStatus.CREATED)
  public async issueKey(@Body() body: IssueAdminApiKeyDto) {
    const { key, plaintextToken } = await this.issueKeyUc.execute({
      name: body.name,
      createdBy: body.createdBy,
      ttlSeconds: body.ttlSeconds,
      notes: body.notes,
    });
    return {
      id: key.id,
      name: key.name,
      plaintextToken, // returned ONCE — never retrievable again
      role: key.role.value,
      expiresAt: key.expiresAt.toISOString(),
      createdAt: key.createdAt.toISOString(),
      createdBy: key.createdBy,
      notes: key.notes,
    };
  }

  @Get('api-keys')
  public listKeys() {
    // Surface only the public-safe fields; never expose the hash.
    // V1: returns empty (no list use-case yet — V1.5 adds it).
    return { keys: [] };
  }

  @Delete('api-keys/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  public async revokeKey(@Param('id') id: string): Promise<void> {
    await this.revokeKeyUc.execute(id);
  }

  @Get('users/:id')
  public async getUser(@Param('id') id: string) {
    return this.getUserUc.execute({ userId: id });
  }

  @Post('users/:id/disable-mfa')
  @HttpCode(HttpStatus.OK)
  public async disableUserMfa(
    @Param('id') id: string,
    @Body() body: AdminDisableUserMfaDto,
    @Req() req: Request,
  ) {
    const adminKeyId = getAdminKeyId(req);
    const result = await this.adminDisableMfaUc.execute({
      userId: id,
      adminKeyId,
      reason: body.reason,
    });
    return {
      userId: result.userId,
      adminKeyId: result.adminKeyId,
      occurredAt: result.occurredAt.toISOString(),
    };
  }

  @Get('audit-log')
  public async searchAuditLog(
    @Query('userId') userId?: string,
    @Query('eventType') eventType?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    const limitNum = limit !== undefined ? Number(limit) : null;
    const offsetNum = offset !== undefined ? Number(offset) : null;
    const fromDate = from ? new Date(from) : null;
    const toDate = to ? new Date(to) : null;
    const result = await this.adminSearchAuditLogUc.execute({
      userId: userId ?? null,
      eventType: eventType ?? null,
      limit: Number.isFinite(limitNum) ? limitNum : null,
      offset: Number.isFinite(offsetNum) ? offsetNum : null,
      from: fromDate,
      to: toDate,
    });
    return {
      entries: result.entries.map((e) => ({
        ...e,
        createdAt: e.createdAt.toISOString(),
      })),
      total: result.total,
    };
  }
}
