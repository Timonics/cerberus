import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Composite filter for the admin audit-log search endpoint.
 *
 * V1 supports:
 *   * `userId` — exact match
 *   * `eventType` — exact match (the stable code from
 *     `AUDIT_EVENT_TYPES` in the Engagement BC)
 *   * `from` / `to` — inclusive lower bound, exclusive upper bound
 *   * `limit` — bounded to [1, 500]
 *   * `offset` — bounded to [0, 10_000] (admin queries shouldn't be
 *     unbounded)
 *
 * At least one filter field must be set, otherwise the query would
 * return the entire audit table. We throw `DomainError` if all are
 * empty.
 */
export interface AdminAuditSearchQuery {
  readonly userId?: string;
  readonly eventType?: string;
  readonly from?: Date;
  readonly to?: Date;
  readonly limit?: number;
  readonly offset?: number;
}

export interface AdminAuditSearchQueryInput {
  userId?: string | null;
  eventType?: string | null;
  from?: Date | null;
  to?: Date | null;
  limit?: number | null;
  offset?: number | null;
}

export function buildAdminAuditSearchQuery(
  input: AdminAuditSearchQueryInput,
): AdminAuditSearchQuery {
  const limit = clampInt(input.limit ?? 100, 1, 500, 'limit');
  const offset = clampInt(input.offset ?? 0, 0, 10_000, 'offset');

  const userId = input.userId?.trim() || undefined;
  const eventType = input.eventType?.trim() || undefined;
  const from = input.from ?? undefined;
  const to = input.to ?? undefined;

  if (!userId && !eventType && !from && !to) {
    throw new DomainError(
      'admin.audit.search.too_broad',
      'Audit-log search requires at least one filter (userId, eventType, from, or to)',
    );
  }
  if (from && to && from.getTime() > to.getTime()) {
    throw new DomainError(
      'admin.audit.search.invalid_range',
      '`from` must be <= `to`',
    );
  }
  return { userId, eventType, from, to, limit, offset };
}

function clampInt(
  value: number,
  min: number,
  max: number,
  field: string,
): number {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new DomainError(
      'admin.audit.search.invalid_int',
      `\`${field}\` must be an integer`,
    );
  }
  if (value < min || value > max) {
    throw new DomainError(
      'admin.audit.search.out_of_range',
      `\`${field}\` must be in [${min}, ${max}]`,
    );
  }
  return value;
}
