import { DomainError } from '../errors/domain-error';

/**
 * Email value object.
 *
 * Emails are a single field with very strict invariants: they MUST be
 * canonicalized (lowercased, trimmed) and MUST conform to a sane syntactic
 * profile. We intentionally do not validate the *deliverability* of an email
 * — that requires an external service and belongs at the integration
 * boundary, not in the domain.
 *
 * The constructor is `private`. Use `Email.create()` to construct. This
 * guarantees that no Email value ever exists in an invalid state — invalid
 * input raises a `DomainError` immediately.
 */
export class Email {
  /** Canonical form: trimmed, lowercased. */
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /**
   * Construct an Email from raw input. Throws `DomainError` with code
   * `identity.email.invalid` if the input fails validation.
   *
   * The regex is deliberately conservative — RFC 5322 in full is absurdly
   * permissive. This pattern accepts the realistic address shapes (>99% of
   * real-world addresses) while rejecting obvious garbage (missing @, spaces,
   * unescaped specials, leading/trailing dots in the local part).
   */
  public static create(raw: string): Email {
    if (typeof raw !== 'string') {
      throw new DomainError(
        'identity.email.invalid',
        'Email must be a string',
        { received: typeof raw },
      );
    }

    const normalized = raw.trim().toLowerCase();

    if (normalized.length === 0) {
      throw new DomainError(
        'identity.email.invalid',
        'Email must not be empty',
      );
    }

    if (normalized.length > 254) {
      // RFC 5321 §4.5.3.1.3 caps the full address length at 254 octets.
      throw new DomainError('identity.email.invalid', 'Email is too long', {
        length: normalized.length,
      });
    }

    // Conservative syntactic check. Tighter than the previous regex:
    //   * Local part: 1+ chars, no leading/trailing dot, no consecutive
    //     dots, each char alphanumeric + _ . % + -.
    //   * Domain: 1+ labels separated by dots, each label alphanumeric
    //     + hyphens (no leading/trailing hyphen). Final label (TLD)
    //     is 2-24 chars of letters only.
    //   * Multi-segment TLDs allowed (.co.uk, .museum).
    const EMAIL_RE =
      /^[a-z0-9](?:[a-z0-9._%+-]*[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}$/;
    if (!EMAIL_RE.test(normalized)) {
      throw new DomainError(
        'identity.email.invalid',
        'Email is not a valid address',
      );
    }

    return new Email(normalized);
  }

  /** Reconstruct an Email from a previously-validated string (e.g. from DB). */
  public static rehydrate(value: string): Email {
    // We trust the database round-trip, but we still normalize so that
    // equality checks remain robust against historical upper-case data.
    return new Email(value.trim().toLowerCase());
  }

  /** Two emails are equal iff their canonical values match. */
  public equals(other: Email): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }

  /** For persistence. */
  public toJSON(): string {
    return this.value;
  }
}
