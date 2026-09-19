import { randomBytes } from 'node:crypto';
import { Clock, DomainError } from '../../../shared/domain';
import { AppApiKey } from './app-api-key';

/**
 * A registered third-party application that integrates with Cerberus.
 *
 * Apps identify themselves via `X-Cerberus-App-Id` + `X-Cerberus-App-Secret`
 * headers. When a register call carries valid credentials, the new user
 * is auto-bound to `defaultOrgSlug` instead of falling through to
 * email-domain matching or auto-creating a personal org.
 *
 * Lifecycle:
 *   * `register()` — open to the public. Returns the app + a fresh
 *     `AppApiKey` aggregate. Plaintext is returned ONCE.
 *   * `revoke()` — soft-revoke (sets `revokedAt`). Future calls with
 *     the app's keys fail at the guard.
 *   * `rotateKey()` — mints a new `AppApiKey`, returns both the new
 *     aggregate + plaintext. Old keys continue to work until manually
 *     revoked (V1.5 will add auto-revoke-on-rotate).
 */
export class App {
  private constructor(
    public readonly id: string,
    public readonly name: string,
    public readonly description: string | null,
    public readonly defaultOrgSlug: string | null,
    public readonly createdAt: Date,
    public readonly contactEmail: string,
    public readonly revokedAt: Date | null,
    public readonly notes: string | null,
    public readonly currentKey: AppApiKey | null,
  ) {}

  public static register(params: {
    id: string;
    name: string;
    description: string | null;
    defaultOrgSlug: string | null;
    contactEmail: string;
    clock: Clock;
    notes?: string;
    /** Pre-generated `AppApiKey` aggregate. */
    initialKey: AppApiKey;
  }): App {
    const now = params.clock.now();
    return new App(
      params.id,
      params.name.trim(),
      params.description?.trim() ?? null,
      params.defaultOrgSlug?.trim() ?? null,
      now,
      params.contactEmail.trim().toLowerCase(),
      null,
      params.notes?.trim() ?? null,
      params.initialKey,
    );
  }

  public static rehydrate(params: {
    id: string;
    name: string;
    description: string | null;
    defaultOrgSlug: string | null;
    createdAt: Date;
    contactEmail: string;
    revokedAt: Date | null;
    notes: string | null;
    currentKey: AppApiKey | null;
  }): App {
    return new App(
      params.id,
      params.name,
      params.description,
      params.defaultOrgSlug,
      params.createdAt,
      params.contactEmail,
      params.revokedAt,
      params.notes,
      params.currentKey,
    );
  }

  public revoke(clock: Clock): App {
    if (this.revokedAt !== null) return this;
    return new App(
      this.id,
      this.name,
      this.description,
      this.defaultOrgSlug,
      this.createdAt,
      this.contactEmail,
      clock.now(),
      this.notes,
      this.currentKey,
    );
  }

  public rotateKey(newKey: AppApiKey): App {
    if (this.revokedAt !== null) {
      throw new DomainError(
        'app.revoked',
        'Cannot rotate keys on a revoked app',
        { appId: this.id },
      );
    }
    return new App(
      this.id,
      this.name,
      this.description,
      this.defaultOrgSlug,
      this.createdAt,
      this.contactEmail,
      this.revokedAt,
      this.notes,
      newKey,
    );
  }

  public isAliveAt(): boolean {
    if (this.revokedAt !== null) return false;
    return true;
  }

  public hasOrgBinding(): boolean {
    return this.defaultOrgSlug !== null && this.defaultOrgSlug.length > 0;
  }
}

/**
 * Generate a fresh 32-byte base64url-encoded app API key plaintext.
 * 256 bits of entropy; argon2id-hashed before storage.
 */
export function generateAppApiKeyPlaintext(): string {
  return randomBytes(32).toString('base64url');
}
