import {
  EntityId,
  assertUuid,
} from '../../../shared/domain/value-objects/entity-id';

export class SessionId extends EntityId<'Session'> {
  private static readonly BRAND = 'Session' as const;

  public static create(raw: string): SessionId {
    assertUuid(raw, 'SessionId');
    return new SessionId(raw);
  }

  public static rehydrate(raw: string): SessionId {
    assertUuid(raw, 'SessionId');
    return new SessionId(raw);
  }

  protected constructor(value: string) {
    super(value);
  }

  protected get brand(): 'Session' {
    return SessionId.BRAND;
  }
}
