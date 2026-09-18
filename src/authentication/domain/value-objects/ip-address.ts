import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * IPv4 or IPv6 address. Validates a sane shape; we do not enforce
 * RFC-strict parsing — the goal is to reject obvious garbage, not to
 * catch every edge case (which the OS would do anyway).
 */
export class IpAddress {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  public static create(raw: string): IpAddress {
    if (typeof raw !== 'string' || raw.length === 0) {
      throw new DomainError(
        'domain.invariant_violation',
        'IpAddress must be a non-empty string',
      );
    }
    if (raw.length > 64) {
      throw new DomainError(
        'domain.invariant_violation',
        'IpAddress is too long',
        { length: raw.length },
      );
    }
    // IPv4 dotted quad OR IPv6 colon-hex (loose). Rejects whitespace and
    // any character outside the IP alphabet.
    if (!/^[0-9a-fA-F.:]+$/.test(raw)) {
      throw new DomainError(
        'domain.invariant_violation',
        'IpAddress contains invalid characters',
      );
    }
    return new IpAddress(raw);
  }

  public static rehydrate(value: string): IpAddress {
    return new IpAddress(value);
  }

  public toString(): string {
    return this.value;
  }
}
