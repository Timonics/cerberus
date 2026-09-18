import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * User-Agent string. Truncated to 1024 chars to keep storage bounded.
 *
 * Real-world UA strings are rarely > 512 chars; the cap is just a
 * safety belt against pathological clients sending megabytes of UA.
 */
export class UserAgent {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  public static create(raw: string): UserAgent {
    if (typeof raw !== 'string') {
      throw new DomainError(
        'domain.invariant_violation',
        'UserAgent must be a string',
      );
    }
    if (raw.length > 1024) {
      return new UserAgent(raw.slice(0, 1024));
    }
    return new UserAgent(raw);
  }

  public static rehydrate(value: string): UserAgent {
    return new UserAgent(value);
  }

  /**
   * Best-effort device label derived from the UA. Pure function used by
   * the session repository when persisting — the caller doesn't have to
   * repeat the regex.
   *
   * Examples:
   *   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
   *     → "Chrome on Windows"
   *   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
   *     → "Mobile Safari on iOS"
   */
  public deviceLabel(): string {
    const ua = this.value;
    const browser = /Edg\//.test(ua)
      ? 'Edge'
      : /OPR\//.test(ua)
        ? 'Opera'
        : /Chrome\//.test(ua)
          ? 'Chrome'
          : /Firefox\//.test(ua)
            ? 'Firefox'
            : /Safari\//.test(ua)
              ? 'Safari'
              : 'Unknown browser';
    const os = /Windows NT/.test(ua)
      ? 'Windows'
      : /Mac OS X/.test(ua)
        ? 'macOS'
        : /iPhone|iPad/.test(ua)
          ? 'iOS'
          : /Android/.test(ua)
            ? 'Android'
            : /Linux/.test(ua)
              ? 'Linux'
              : 'Unknown OS';
    const mobile = /Mobile/.test(ua) ? 'Mobile ' : '';
    return `${mobile}${browser} on ${os}`;
  }

  public toString(): string {
    return this.value;
  }
}
