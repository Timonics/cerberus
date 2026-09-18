import {
  EntityId,
  assertUuid,
} from '../../../shared/domain/value-objects/entity-id';

/**
 * Organization aggregate ID.
 *
 * The Organization is the tenant root: every User belongs to one Organization,
 * roles are scoped to an Organization, audit log entries are scoped to an
 * Organization, and the JWT `org` claim is populated from the Organization.
 *
 * See `UserId` for the rationale behind the brand pattern.
 */
export class OrgId extends EntityId<'Org'> {
  private static readonly BRAND = 'Org' as const;

  public static create(raw: string): OrgId {
    assertUuid(raw, 'OrgId');
    return new OrgId(raw);
  }

  public static rehydrate(raw: string): OrgId {
    assertUuid(raw, 'OrgId');
    return new OrgId(raw);
  }

  protected constructor(value: string) {
    super(value);
  }

  protected get brand(): 'Org' {
    return OrgId.BRAND;
  }
}
