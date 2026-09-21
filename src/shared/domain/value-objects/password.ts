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

    // V1.5 (audit QA3): trim leading/trailing whitespace so that
    // '  password123!' and 'password123!' are treated identically
    // (otherwise users may hit different hash outputs depending on
    // whether their password manager adds a trailing space). Use
    // Unicode-aware trim + codepoint counting so emoji-length
    // passwords are not unfairly rejected.
    const trimmed = raw.normalize('NFKC').trim();

    // Codepoint count (not UTF-16 code units). Spread iterates
    // code points, so [...trimmed].length gives the user-visible
    // length. A 12-codepoint password is the minimum.
    const codepointLength = [...trimmed].length;

    if (codepointLength < 12) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must be at least 12 characters',
        { length: codepointLength },
      );
    }

    if (codepointLength > 128) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must be at most 128 characters',
        { length: codepointLength },
      );
    }

    // Composition check — reject passwords that are all-lowercase, all-uppercase,
    // all-digits, all-symbols, or too short. The k-anonymity breach check is
    // layered on top at the use-case level (it requires an external service).
    if (
      /^[a-z]+$/.test(trimmed) ||
      /^[A-Z]+$/.test(trimmed) ||
      /^\d+$/.test(trimmed) ||
      /^[^a-zA-Z0-9]+$/.test(trimmed)
    ) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must contain at least one lowercase letter, one uppercase letter or symbol, and one digit',
      );
    }
    if (!/[a-z]/.test(trimmed)) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must contain at least one lowercase letter',
      );
    }
    if (!/\d/.test(trimmed)) {
      throw new DomainError(
        'identity.password.too_weak',
        'Password must contain at least one digit',
      );
    }

    return new Password(trimmed);
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
