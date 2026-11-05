import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Service slug value object.
 *
 * URL-safe identifier for a catalog Service (e.g. "calliope"). The slug
 * is ALSO the suffix of the OAuth2 scope minted onto org members' access
 * tokens (`service:<slug>`), so it must satisfy the scope grammar in
 * `authorization/domain/value-objects/scope.ts` — total scope length
 * ≤ 64 chars, hence the 56-char cap here (8 chars for the `service:`
 * prefix).
 *
 * Format: lowercase letters, digits, hyphens. Length 2–56. Cannot start
 * or end with a hyphen.
 */
export class ServiceSlug {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  public static create(raw: string): ServiceSlug {
    if (typeof raw !== 'string') {
      throw new DomainError(
        'domain.invariant_violation',
        'ServiceSlug must be a string',
      );
    }
    const normalized = raw.trim().toLowerCase();

    if (normalized.length < 2 || normalized.length > 56) {
      throw new DomainError(
        'domain.invariant_violation',
        'ServiceSlug must be 2–56 characters',
        { length: normalized.length },
      );
    }
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(normalized)) {
      throw new DomainError(
        'domain.invariant_violation',
        'ServiceSlug may only contain lowercase letters, digits, and hyphens, and cannot start or end with a hyphen',
      );
    }

    return new ServiceSlug(normalized);
  }

  public static rehydrate(value: string): ServiceSlug {
    return new ServiceSlug(value);
  }

  public equals(other: ServiceSlug): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }
}
