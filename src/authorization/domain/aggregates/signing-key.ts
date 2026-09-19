import { Clock, DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';

/**
 * A single signing keypair.
 *
 * Each row in `signing_keys` represents one RSA key. One is `isCurrent`
 * at a time (the one that signs new tokens); older keys remain valid
 * for verification until their `expiresAt` (so tokens issued during a
 * rotation window still verify). `retiredAt` marks when the key stopped
 * being used for signing.
 *
 * `kid` is the key identifier — it's exposed in the JWT header
 * (`{ "alg": "RS256", "kid": "...", "typ": "JWT" }`) and in the JWKS.
 *
 * Invariants:
 *   * `privatePem` and `publicPem` are PEM-encoded PKCS#8 / SPKI.
 *   * At most one row has `isCurrent = true` at any moment.
 *   * `retiredAt` is set BEFORE `expiresAt`; both are set when the key
 *     is no longer current. Newly-created keys have both `null`.
 */
export class SigningKey {
  private constructor(
    public readonly id: string,
    public readonly kid: string,
    public readonly algorithm: string,
    public readonly privatePem: string,
    public readonly publicPem: string,
    public readonly createdAt: Date,
    public readonly retiredAt: Date | null,
    public readonly expiresAt: Date | null,
    public readonly isCurrent: boolean,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  // -------------------------------------------------------------------------
  // Factory: new keypair (about to become current)
  // -------------------------------------------------------------------------

  public static create(params: {
    id: string;
    kid: string;
    algorithm: string;
    privatePem: string;
    publicPem: string;
    clock: Clock;
  }): SigningKey {
    const now = params.clock.now();
    return new SigningKey(
      params.id,
      params.kid,
      params.algorithm,
      params.privatePem,
      params.publicPem,
      now,
      null,
      null,
      true, // a brand-new key is current by default
      [],
    );
  }

  // -------------------------------------------------------------------------
  // Factory: rehydrate from persistence
  // -------------------------------------------------------------------------

  public static fromPersistence(params: {
    id: string;
    kid: string;
    algorithm: string;
    privatePem: string;
    publicPem: string;
    createdAt: Date;
    retiredAt: Date | null;
    expiresAt: Date | null;
    isCurrent: boolean;
  }): SigningKey {
    return new SigningKey(
      params.id,
      params.kid,
      params.algorithm,
      params.privatePem,
      params.publicPem,
      params.createdAt,
      params.retiredAt,
      params.expiresAt,
      params.isCurrent,
      [],
    );
  }

  /**
   * Mark this key as no longer current. Sets `retiredAt` to now and
   * clears `isCurrent`. The key continues to verify until `expiresAt`.
   *
   * Idempotent — calling twice has no effect.
   */
  public retire(clock: Clock, verificationGraceSeconds: number): SigningKey {
    if (this.retiredAt !== null || !this.isCurrent) {
      return this;
    }
    const now = clock.now();
    return new SigningKey(
      this.id,
      this.kid,
      this.algorithm,
      this.privatePem,
      this.publicPem,
      this.createdAt,
      now,
      new Date(now.getTime() + verificationGraceSeconds * 1000),
      false,
      this.pendingEvents,
    );
  }

  /** True if the key is current AND can sign new tokens. */
  public canSign(): boolean {
    return this.isCurrent && this.retiredAt === null;
  }

  /**
   * True if the key can be used to verify a token (current, or retired
   * but not yet expired).
   */
  public canVerifyAt(when: Date): boolean {
    if (this.expiresAt !== null && this.expiresAt.getTime() <= when.getTime()) {
      return false;
    }
    return true;
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}

/**
 * Standard grace period for verification after a key is rotated.
 *
 * The old key signs no new tokens after `retiredAt`, but tokens signed
 * BEFORE that moment remain valid for verification until
 * `retiredAt + gracePeriod`. Default: 24 hours — long enough for any
 * legitimate access-token lifetime, short enough to bound the window
 * of a compromised old key.
 */
export const DEFAULT_VERIFICATION_GRACE_SECONDS = 24 * 60 * 60;

/**
 * Validate the format of an RSA keypair's PEM strings. We do a quick
 * presence check — full validation is the responsibility of the
 * signing library (`jose`).
 */
export function assertKeyFormat(privatePem: string, publicPem: string): void {
  if (
    !privatePem.includes('BEGIN PRIVATE KEY') &&
    !privatePem.includes('BEGIN RSA PRIVATE KEY')
  ) {
    throw new DomainError(
      'domain.invariant_violation',
      'privatePem is not a valid PEM-encoded private key',
    );
  }
  if (!publicPem.includes('BEGIN PUBLIC KEY')) {
    throw new DomainError(
      'domain.invariant_violation',
      'publicPem is not a valid PEM-encoded public key',
    );
  }
}
