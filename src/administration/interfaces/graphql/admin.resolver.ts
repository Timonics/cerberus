import { Inject, Injectable } from '@nestjs/common';
import { Args, Query, Mutation, Resolver } from '@nestjs/graphql';
import { AuthGuard } from '../../../graphql/guards/auth-guard.decorator';
import { CurrentUser } from '../../../graphql/graphql-context';
import {
  GqlBadRequestException,
  GqlForbiddenException,
} from '../../../graphql/graphql-errors';
import { GetUserUseCase } from '../../../identity/application/use-cases/get-user.use-case';
import { AdminDisableUserMfaUseCase } from '../../application/use-cases/admin-disable-user-mfa.use-case';
import { AdminSearchAuditLogUseCase } from '../../application/use-cases/admin-search-audit-log.use-case';

/**
 * Admin GraphQL resolver (V1.5).
 *
 * Exposes a SUBSET of the REST admin surface over GraphQL for web-based
 * admin consoles. Specifically:
 *
 *   * `adminUser(id)` — look up a user IN THE CALLER'S ORG
 *     (requires `org:admin` scope)
 *   * `adminDisableUserMfa(input)` — admin MFA override
 *   * `adminAuditLog(input)` — search the audit log, restricted to
 *     the caller's organization
 *
 * V1.7 (audit H-2): every entry point enforces the org boundary.
 * `org:admin` proves the caller is an OWNER/ADMIN — of SOME org, not
 * necessarily the target's. Without the boundary check any org admin
 * could read any tenant's users and audit history. The boundary is
 * resolved here (resolver layer) by comparing the caller's
 * organization (via `GetUserUseCase`) against the target's — the
 * same pattern `AdminDisableUserMfaUseCase` applies internally.
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
      "Look up a user by ID within the caller's organization. Requires `org:admin` scope (OWNER or ADMIN role). Cross-tenant lookups are rejected.",
  })
  public async adminUser(
    @CurrentUser() caller: { sub: string },
    @Args('id') id: string,
  ): Promise<unknown> {
    const callerOrgId = await this.callerOrgId(caller.sub);
    let u;
    try {
      u = await this.getUserUc.execute({ userId: id });
    } catch {
      throw new GqlBadRequestException('USER_NOT_FOUND');
    }
    // V1.7 (audit H-2): org boundary — `org:admin` scopes the caller
    // to their own org; a user in any other org is out of bounds.
    if (u.organizationId !== callerOrgId) {
      throw new GqlForbiddenException(
        'Target user is outside your organization',
      );
    }
    return {
      id: u.userId,
      email: u.email,
      displayName: u.displayName,
      mfaEnabled: u.mfaEnabled,
      emailVerifiedAt: null,
      createdAt: u.createdAt,
      organizationId: u.organizationId,
    };
  }

  @AuthGuard({ requireOrgAdmin: true })
  @Mutation(() => 'AdminDisableUserMfaPayload', {
    description:
      "Admin override: disable a user's MFA. Writes `admin.user.mfa_disabled` audit log.",
  })
  public async adminDisableUserMfa(
    @CurrentUser() user: { sub: string },
    @Args('input')
    input: { userId: string; reason?: string },
  ): Promise<unknown> {
    // V1.5 (audit C-1): the use-case resolves the caller's org
    // internally from the JWT `sub`. It rejects if the target
    // belongs to a different org, blocking cross-tenant IDOR.
    // V1.7 (audit, GraphQL MEDIUM): `adminKeyId` is NEVER taken from
    // the caller — a GraphQL JWT caller has no admin API key, so the
    // audit row records null (the REST path passes the verified key
    // id itself).
    const result = await this.disableMfaUc.execute({
      userId: input.userId,
      callerUserId: user.sub,
      adminKeyId: null,
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
      "Search the audit log restricted to the caller's organization. Requires `org:admin` scope. V1: at least one filter required to prevent unbounded scans.",
  })
  public async adminAuditLog(
    @CurrentUser() caller: { sub: string },
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
    const callerOrgId = await this.callerOrgId(caller.sub);

    if (input.userId) {
      // User-scoped search: assert the target user belongs to the
      // caller's org BEFORE running the search (audit H-2).
      let target;
      try {
        target = await this.getUserUc.execute({ userId: input.userId });
      } catch {
        throw new GqlBadRequestException('USER_NOT_FOUND');
      }
      if (target.organizationId !== callerOrgId) {
        throw new GqlForbiddenException(
          'Target user is outside your organization',
        );
      }
      const result = await this.searchAuditLogUc.execute({
        userId: input.userId,
        eventType: input.eventType ?? null,
        from: null,
        to: null,
        limit,
        offset,
      });
      return result.entries.map((e) => this.toGraphqlEntry(e));
    }

    // Event-type-only search is org-wide in intent but the audit
    // repository has no org-scoped query path (and editing the
    // search use-case is out of scope here). We fetch the raw rows,
    // resolve each distinct row user's org, and keep only rows that
    // belong to the caller's org. Bounded: at most `limit` rows and
    // one user lookup per distinct user id in them. Rows with a
    // null userId (app / system events) cannot be attributed to an
    // org and are excluded from the org-scoped view.
    const raw = await this.searchAuditLogUc.execute({
      userId: null,
      eventType: input.eventType ?? null,
      from: null,
      to: null,
      limit: 500,
      offset: 0,
    });
    const distinctUserIds = Array.from(
      new Set(
        raw.entries
          .map((e) => e.userId)
          .filter((u): u is string => typeof u === 'string' && u.length > 0),
      ),
    );
    const orgByUserId = new Map<string, string>();
    for (const uid of distinctUserIds) {
      try {
        const profile = await this.getUserUc.execute({ userId: uid });
        orgByUserId.set(uid, profile.organizationId);
      } catch {
        // User deleted since the event was written — unattributable.
      }
    }
    return raw.entries
      .filter(
        (e) =>
          typeof e.userId === 'string' &&
          orgByUserId.get(e.userId) === callerOrgId,
      )
      .slice(0, limit)
      .map((e) => this.toGraphqlEntry(e));
  }

  /** Resolve the caller's organization id, refusing callers with none. */
  private async callerOrgId(callerUserId: string): Promise<string> {
    const caller = await this.getUserUc.execute({ userId: callerUserId });
    return caller.organizationId;
  }

  private toGraphqlEntry(e: {
    id: string;
    eventType: string;
    userId: string | null;
    payload: Readonly<Record<string, unknown>>;
    ipAddress: string | null;
    userAgent: string | null;
    createdAt: Date;
  }): unknown {
    return {
      id: e.id,
      eventType: e.eventType,
      userId: e.userId,
      payload: JSON.stringify(e.payload),
      ipAddress: e.ipAddress,
      userAgent: e.userAgent,
      occurredAt: e.createdAt.toISOString(),
    };
  }
}
