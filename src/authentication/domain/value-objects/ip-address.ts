import { isIP } from 'node:net';
import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * IPv4 or IPv6 address. Validated with Node's built-in `net.isIP()`,
 * which accepts every canonical form:
 *   * IPv4: `127.0.0.1`, `0.0.0.0`, `255.255.255.255`
 *   * IPv6: `::1`, `2001:db8::1`, `fe80::1%eth0` (with zone)
 *   * IPv4-mapped IPv6: `::ffff:127.0.0.1`
 *
 * Loose forms like `1.2.3` (3-octet) or `2001:db8::g` (non-hex) are
 * rejected.
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
    // net.isIP returns 4 for valid IPv4, 6 for valid IPv6, 0 for invalid.
    // It correctly rejects "1.2.3" (3 octets), "::ffff:256.0.0.1" (out of
    // range), and "2001:db8::g" (non-hex).
    if (isIP(raw) === 0) {
      throw new DomainError(
        'domain.invariant_violation',
        'IpAddress is not a valid IPv4 or IPv6 address',
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
