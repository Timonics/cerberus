import { Inject, Injectable } from '@nestjs/common';
import { Args, Query, Mutation, Resolver } from '@nestjs/graphql';
import { AuthGuard } from '../../../graphql/guards/auth-guard.decorator';
import { CurrentUser } from '../../../graphql/graphql-context';
import { GqlBadRequestException } from '../../../graphql/graphql-errors';
import { GetUserUseCase } from '../../../identity/application/use-cases/get-user.use-case';
import { AdminDisableUserMfaUseCase } from '../../application/use-cases/admin-disable-user-mfa.use-case';
import { AdminSearchAuditLogUseCase } from '../../application/use-cases/admin-search-audit-log.use-case';

/**
 * Admin GraphQL resolver (V1.5).
 *
 * Exposes a SUBSET of the REST admin surface over GraphQL for web-based
 * admin consoles. Specifically:
 *
 *   * `adminUser(id)` — look up any user (requires `org:admin` scope)
 *   * `adminDisableUserMfa(input)` — admin MFA override
 *   * `adminAuditLog(input)` — search audit log
 *
 * Admin API-key operations (issue / list / revoke) stay REST-only on
 * the admin listener. The reasoning:
 *
 *   1. Admin API keys are typically managed by CI/bots, not by
 *      interactive UIs. REST is fine.
 *   2. Surfacing them in GraphQL would require the operator's JWT
 *      to carry the `admin:apikey:write` scope — a scope only
 *      the SUPER_ADMIN role has. We'd need a role lookup in the
 *      GraphQL context that we don't have today.
 *
 * V1.5 ships the user-facing subset. The REST endpoints stay
 * unchanged for CI integrations.
 */
@Injectable()
@Resolver(() => 'Query')
export class AdminGraphqlResolver {
  public constructor(
    @Inject(GetUserUseCase) private readonly getUserUc: GetUserUseCase,
    @Inject(AdminDisableUserMfaUseCase)
    private readonly disableMfaUc: AdminDisableUserMfaUseCase,
    @Inject(AdminSearchAuditLogUseCase)
    private readonly searchAuditLogUc: AdminSearchAuditLogUseCase,
  ) {}

  @AuthGuard({ requireOrgAdmin: true })
  @Query(() => 'AdminUserView', {
    description:
      'Look up any user by ID. Requires `org:admin` scope (OWNER or ADMIN role).',
  })
  public async adminUser(@Args('id') id: string): Promise<unknown> {
    try {
      const u = await this.getUserUc.execute({ userId: id });
      return {
        id: u.userId,
        email: u.email,
        displayName: u.displayName,
        mfaEnabled: u.mfaEnabled,
        emailVerifiedAt: null,
        createdAt: u.createdAt,
        organizationId: u.organizationId,
      };
    } catch {
      throw new GqlBadRequestException('USER_NOT_FOUND');
    }
  }

  @AuthGuard({ requireOrgAdmin: true })
  @Mutation(() => 'AdminDisableUserMfaPayload', {
    description:
      "Admin override: disable a user's MFA. Writes `admin.user.mfa_disabled` audit log.",
  })
  public async adminDisableUserMfa(
    @CurrentUser() user: { sub: string },
    @Args('input')
    input: { userId: string; adminKeyId?: string; reason?: string },
  ): Promise<unknown> {
    // V1.5 (audit C-1): the use-case resolves the caller's org
    // internally from the JWT `sub`. It rejects if the target
    // belongs to a different org, blocking cross-tenant IDOR.
    const result = await this.disableMfaUc.execute({
      userId: input.userId,
      callerUserId: user.sub,
      adminKeyId: input.adminKeyId ?? null,
      reason: input.reason ?? null,
    });
    return {
      userId: result.userId,
      adminKeyId: result.adminKeyId,
      occurredAt: result.occurredAt.toISOString(),
    };
  }

  @AuthGuard({ requireOrgAdmin: true })
  @Query(() => '[AuditLogEntry!]!', {
    description:
      'Search the audit log. Requires `org:admin` scope. V1: at least one filter required to prevent unbounded scans.',
  })
  public async adminAuditLog(
    @Args('input')
    input: {
      userId?: string;
      eventType?: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<unknown[]> {
    const limit = input.limit ?? 100;
    const offset = input.offset ?? 0;
    if (!input.userId && !input.eventType) {
      throw new GqlBadRequestException('AUDIT_SEARCH_TOO_BROAD');
    }
    if (limit < 1 || limit > 500) {
      throw new GqlBadRequestException('AUDIT_SEARCH_OUT_OF_RANGE');
    }
    const result = await this.searchAuditLogUc.execute({
      userId: input.userId ?? null,
      eventType: input.eventType ?? null,
      from: null,
      to: null,
      limit,
      offset,
    });
    return result.entries.map((e) => ({
      id: e.id,
      eventType: e.eventType,
      userId: e.userId,
      payload: JSON.stringify(e.payload),
      ipAddress: e.ipAddress,
      userAgent: e.userAgent,
      occurredAt: e.createdAt.toISOString(),
    }));
  }
}
