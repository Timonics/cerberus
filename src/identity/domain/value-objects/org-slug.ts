import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Organization slug value object.
 *
 * A slug is a URL-safe identifier for an Organization (e.g. "acme-corp").
 * It's exposed in JWTs, audit logs, and admin URLs instead of the raw
 * UUID — much easier to read in production logs.
 *
 * Format: lowercase letters, digits, and hyphens. Length 3–63. Cannot
 * start or end with a hyphen.
 */
export class OrgSlug {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  public static create(raw: string): OrgSlug {
    if (typeof raw !== 'string') {
      throw new DomainError(
        'domain.invariant_violation',
        'OrgSlug must be a string',
      );
    }
    const normalized = raw.trim().toLowerCase();

    if (normalized.length < 3 || normalized.length > 63) {
      throw new DomainError(
        'domain.invariant_violation',
        'OrgSlug must be 3–63 characters',
        { length: normalized.length },
      );
    }
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(normalized)) {
      throw new DomainError(
        'domain.invariant_violation',
        'OrgSlug may only contain lowercase letters, digits, and hyphens, and cannot start or end with a hyphen',
      );
    }

    return new OrgSlug(normalized);
  }

  public static rehydrate(value: string): OrgSlug {
    return new OrgSlug(value);
  }

  public equals(other: OrgSlug): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }
}
