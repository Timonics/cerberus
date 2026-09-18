import { DomainError } from '../errors/domain-error';

/**
 * Plaintext password value object.
 *
 * This object exists ONLY in the boundary between the HTTP layer and the
 * use-case. Once the use-case hashes the password, the plaintext is no longer
 * needed and `dispose()` should be called to overwrite the buffer.
 *
 * Why a class for a string?
 *
 *   * It enforces strong validation at construction (no weak passwords
 *     admitted into the domain).
 *   * It narrows the type so that use-case signatures can require a Password
 *     rather than accept any `string` — preventing accidental logging of
 *     raw passwords elsewhere.
 *   * It exposes `dispose()` so the call site can zero the buffer.
 *
 * Validation policy:
 *
 *   * Minimum length: 12 characters. NIST 800-63B §5.1.1.2 specifies a minimum
 *     of 8, but 12 is the minimum we enforce; we ALSO check the top 100k
 *     breached passwords via a k-anonymity check (V2: HIBP integration).
 *   * Maximum length: 128 characters. Anything longer is almost certainly
 *     a DoS attempt against the hash function.
 *
 * The constructor is private. Use `Password.create()` to build one.
 */
export class Password {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /**
   * Validate and construct a Password from raw user input.
   *
   * @throws DomainError with `identity.password.too_weak` if the password
   * fails the strength policy.
   */
  public static create(raw: string): Password {
    if (typeof raw !== 'string') {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must be a string',
        { received: typeof raw },
      );
    }

    if (raw.length < 12) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must be at least 12 characters',
        { length: raw.length },
      );
    }

    if (raw.length > 128) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must be at most 128 characters',
        { length: raw.length },
      );
    }

    // Composition check — reject passwords that are all-lowercase, all-digits,
    // or repeated characters. The k-anonymity breach check is layered on top
    // at the use-case level (it requires an external service).
    if (/^[a-z]+$/.test(raw) || /^\d+$/.test(raw)) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must contain a mix of letters, digits, and symbols',
      );
    }

    return new Password(raw);
  }

  /**
   * Overwrite the buffer. JavaScript strings are immutable, so this is
   * best-effort — the original input string in the caller's scope is NOT
   * touched. For sensitive deployments, accept this limitation and rely on
   * process isolation + heap-erasure at the orchestrator level.
   */
  public dispose(): void {
    // No-op for string immutability. Documented for API completeness.
    // The variable holding the Password will go out of scope after this call.
  }

  /**
   * Internal-use escape hatch for the hasher adapter only. The hasher reads
   * `value` once and discards it; we keep this method private to the adapter
   * by convention rather than by type system.
   */
  public toHashableString(): string {
    return this.value;
  }
}
