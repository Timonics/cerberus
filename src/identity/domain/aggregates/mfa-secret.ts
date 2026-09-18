import { DomainError } from '../../../shared/domain';
import { DomainEvent } from '../../../shared/domain/events/domain-event';
import {
  MfaDisabled,
  MfaEnabled,
  MfaEnrollmentStarted,
} from '../events/identity.events';
import { UserId } from '../value-objects/user-id';

/**
 * RecoveryCode value object.
 *
 * A single-use code that the user can present instead of a TOTP code
 * when they have lost their authenticator device. The plaintext is shown
 * to the user exactly once at enrollment; only the argon2id hash is
 * persisted.
 *
 * Created via the factory `RecoveryCode.create()` (which hashes the
 * plaintext) or `RecoveryCode.fromPersistence()` (which trusts the
 * already-stored hash).
 */
export class RecoveryCode {
  private constructor(
    public readonly id: string,
    public readonly mfaSecretId: string,
    public readonly codeHash: string,
    public readonly usedAt: Date | null,
  ) {}

  public static create(params: {
    id: string;
    mfaSecretId: string;
    codeHash: string;
  }): RecoveryCode {
    return new RecoveryCode(
      params.id,
      params.mfaSecretId,
      params.codeHash,
      null,
    );
  }

  public static fromPersistence(params: {
    id: string;
    mfaSecretId: string;
    codeHash: string;
    usedAt: Date | null;
  }): RecoveryCode {
    return new RecoveryCode(
      params.id,
      params.mfaSecretId,
      params.codeHash,
      params.usedAt,
    );
  }

  public markUsed(usedAt: Date): RecoveryCode {
    if (this.usedAt !== null) {
      throw new DomainError(
        'identity.mfa.recovery_code_invalid',
        'Recovery code has already been used',
      );
    }
    return new RecoveryCode(this.id, this.mfaSecretId, this.codeHash, usedAt);
  }

  public isUsed(): boolean {
    return this.usedAt !== null;
  }
}

/**
 * MfaSecret aggregate root.
 *
 * Owns a user's TOTP secret + recovery codes. Has a two-phase lifecycle:
 *
 *   1. **Pending** — secret generated, recovery codes issued, but the user
 *      has not yet confirmed with a valid TOTP code. The secret is stored
 *      but cannot be used to authenticate.
 *
 *   2. **Confirmed** — the user has proven possession of the authenticator
 *      by providing a valid code. From this point on, the secret is used
 *      for second-factor authentication.
 *
 * The aggregate ALSO owns its set of recovery codes; the recovery codes
 * are loaded together with the secret and decisions about whether a code
 * is valid are made on the loaded collection. This keeps the aggregate
 * consistent (you can't verify a recovery code without also loading the
 * secret for the same user).
 *
 * Domain events emitted:
 *
 *   * `MfaEnrollmentStarted` — when `enroll()` creates the pending secret.
 *   * `MfaEnabled` — when the user confirms with a valid TOTP code.
 *   * `MfaDisabled` — when MFA is turned off entirely.
 */
export class MfaSecret {
  private constructor(
    public readonly id: string,
    public readonly userId: UserId,
    public readonly secret: string, // base32-encoded TOTP shared secret
    public readonly confirmed: boolean,
    public readonly recoveryCodes: ReadonlyArray<RecoveryCode>,
    public readonly createdAt: Date,
    public readonly updatedAt: Date,
    private readonly pendingEvents: DomainEvent[],
  ) {}

  // -------------------------------------------------------------------------
  // Factory: new enrollment (pending)
  // -------------------------------------------------------------------------

  public static enroll(params: {
    id: string;
    userId: UserId;
    secret: string;
    recoveryCodes: ReadonlyArray<RecoveryCode>;
    clock: Clock;
    eventIdGenerator: { generate(): string };
  }): MfaSecret {
    const { id, userId, secret, recoveryCodes, clock, eventIdGenerator } =
      params;
    const now = clock.now();

    if (recoveryCodes.length === 0) {
      throw new DomainError(
        'domain.invariant_violation',
        'MFA enrollment must issue at least one recovery code',
      );
    }

    const event = new MfaEnrollmentStarted(
      eventIdGenerator.generate(),
      now,
      userId,
    );

    return new MfaSecret(
      id,
      userId,
      secret,
      false, // not yet confirmed
      recoveryCodes,
      now,
      now,
      [event],
    );
  }

  // -------------------------------------------------------------------------
  // Factory: rehydrate from persistence
  // -------------------------------------------------------------------------

  public static fromPersistence(params: {
    id: string;
    userId: UserId;
    secret: string;
    confirmed: boolean;
    recoveryCodes: ReadonlyArray<RecoveryCode>;
    createdAt: Date;
    updatedAt: Date;
  }): MfaSecret {
    return new MfaSecret(
      params.id,
      params.userId,
      params.secret,
      params.confirmed,
      params.recoveryCodes,
      params.createdAt,
      params.updatedAt,
      [],
    );
  }

  // -------------------------------------------------------------------------
  // Domain methods
  // -------------------------------------------------------------------------

  /**
   * Confirm enrollment by checking a TOTP code. Only valid in the
   * `pending` state — if the secret is already confirmed, throws.
   *
   * `verifyTotp` is a pure function injected by the infrastructure layer
   * (it knows about the otplib API). The aggregate stays pure TS.
   */
  public confirmEnrollment(params: {
    clock: Clock;
    eventIdGenerator: { generate(): string };
    code: string;
    verifyTotp: (secret: string, code: string) => boolean;
  }): MfaSecret {
    const { clock, eventIdGenerator, code, verifyTotp } = params;

    if (this.confirmed) {
      throw new DomainError(
        'identity.mfa.already_enabled',
        'MFA is already enabled for this user',
      );
    }

    if (!verifyTotp(this.secret, code)) {
      throw new DomainError(
        'identity.mfa.code_invalid',
        'Provided TOTP code does not match the secret',
      );
    }

    const now = clock.now();
    const event = new MfaEnabled(eventIdGenerator.generate(), now, this.userId);

    return new MfaSecret(
      this.id,
      this.userId,
      this.secret,
      true,
      this.recoveryCodes,
      this.createdAt,
      now,
      [...this.pendingEvents, event],
    );
  }

  /**
   * Verify a TOTP code against this secret. Only valid when the secret
   * is already confirmed. Used by the Authentication context on login.
   */
  public verifyTotpCode(
    code: string,
    verifyTotp: (secret: string, code: string) => boolean,
  ): boolean {
    if (!this.confirmed) {
      return false;
    }
    return verifyTotp(this.secret, code);
  }

  /**
   * Verify a recovery code. If the code matches a stored hash and has
   * not been used, marks it as used and returns the updated aggregate.
   * If no match, returns `null` so the caller can distinguish "no such
   * code" from "code already used" via a domain error.
   */
  public async consumeRecoveryCode(params: {
    plaintextCode: string;
    verifyHash: (plaintext: string, hash: string) => Promise<boolean>;
    now: Date;
  }): Promise<{ updated: MfaSecret; matched: boolean; alreadyUsed: boolean }> {
    for (const code of this.recoveryCodes) {
      const ok = await params.verifyHash(params.plaintextCode, code.codeHash);
      if (!ok) continue;

      if (code.isUsed()) {
        return { updated: this, matched: false, alreadyUsed: true };
      }

      const used = code.markUsed(params.now);
      const updatedCodes = this.recoveryCodes.map((c) =>
        c.id === used.id ? used : c,
      );
      const updated = new MfaSecret(
        this.id,
        this.userId,
        this.secret,
        this.confirmed,
        updatedCodes,
        this.createdAt,
        params.now,
        this.pendingEvents,
      );
      return { updated, matched: true, alreadyUsed: false };
    }
    return { updated: this, matched: false, alreadyUsed: false };
  }

  /**
   * Disable MFA entirely. Caller must have verified the user with a
   * fresh TOTP code (defense against an attacker who stole the session
   * cookie and wants to turn off MFA). Throws if the secret isn't yet
   * confirmed.
   */
  public disable(params: {
    clock: Clock;
    eventIdGenerator: { generate(): string };
  }): { id: string; deleted: true; events: DomainEvent[] } {
    const { clock, eventIdGenerator } = params;

    if (!this.confirmed) {
      throw new DomainError(
        'identity.mfa.not_enabled',
        'MFA has not been enabled for this user',
      );
    }

    const now = clock.now();
    const event = new MfaDisabled(
      eventIdGenerator.generate(),
      now,
      this.userId,
    );
    return {
      id: this.id,
      deleted: true,
      events: [...this.pendingEvents, event],
    };
  }

  public pullDomainEvents(): DomainEvent[] {
    return [...this.pendingEvents];
  }
}

// Local alias to avoid pulling Clock from a barrel just for the type.
interface Clock {
  now(): Date;
}
