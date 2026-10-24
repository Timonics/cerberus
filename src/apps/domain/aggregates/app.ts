import { randomBytes } from 'node:crypto';
import { Clock, DomainError } from '../../../shared/domain';
import { AppApiKey } from './app-api-key';
import { filterAppScopes } from '../value-objects/app-scope';

/**
 * Parse a comma-separated scopes string into a deduplicated,
 * trimmed list intersected with the server-side app-scope
 * registry (`filterAppScopes`). Empty / whitespace-only inputs
 * become an empty array — the caller then sees zero scopes
 * (RFC 6749 §3.3: the server is the authority on what's allowed).
 *
 * V1.7 (audit H-3): the registry intersection happens HERE, on
 * the read path, so even a row persisted before the registry
 * existed (holding e.g. `org:admin`) can never widen what a
 * client_credentials token is granted.
 *
 * Used by both the App aggregate (to expose `allowedScopesList`)
 * and the OAuth client_credentials use case (to compute the
 * downgraded scope set).
 */
export function parseScopeList(csv: string): string[] {
  return filterAppScopes(csv.split(','));
}

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
    public readonly contactEmail: string,
    public readonly createdAt: Date,
    public readonly revokedAt: Date | null,
    public readonly notes: string | null,
    public readonly currentKey: AppApiKey | null,
    /**
     * V1.6 client_credentials grant: comma-separated OAuth2 scopes
     * the app is allowed to request via /v1/oauth/token.
     * Parsed on demand via `allowedScopesList` — the raw string
     * is what's persisted, so the JSON column never has to
     * reorder / dedupe on read.
     */
    public readonly allowedScopes: string,
    /**
     * Idempotency key presented at registration, when any. Immutable.
     * A replayed registration with the same key returns THIS app
     * instead of creating a duplicate (the use-case handles the
     * replay; the aggregate just carries the key for persistence).
     */
    public readonly idempotencyKey: string | null,
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
    /** V1.6: comma-separated OAuth2 scopes the app may request. */
    allowedScopes?: string;
    /** Idempotency key presented at registration, when any. */
    idempotencyKey?: string | null;
  }): App {
    const now = params.clock.now();
    return new App(
      params.id,
      params.name.trim(),
      params.description?.trim() ?? null,
      params.defaultOrgSlug?.trim() ?? null,
      params.contactEmail.trim().toLowerCase(),
      now,
      null,
      params.notes?.trim() ?? null,
      params.initialKey,
      params.allowedScopes?.trim() ?? '',
      params.idempotencyKey?.trim() || null,
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
    allowedScopes?: string;
    idempotencyKey?: string | null;
  }): App {
    return new App(
      params.id,
      params.name,
      params.description,
      params.defaultOrgSlug,
      params.contactEmail,
      params.createdAt,
      params.revokedAt,
      params.notes,
      params.currentKey,
      params.allowedScopes ?? '',
      params.idempotencyKey ?? null,
    );
  }

  public revoke(clock: Clock): App {
    if (this.revokedAt !== null) return this;
    return new App(
      this.id,
      this.name,
      this.description,
      this.defaultOrgSlug,
      this.contactEmail,
      this.createdAt,
      clock.now(),
      this.notes,
      this.currentKey,
      this.allowedScopes,
      this.idempotencyKey,
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
      this.contactEmail,
      this.createdAt,
      this.revokedAt,
      this.notes,
      newKey,
      this.allowedScopes,
      this.idempotencyKey,
    );
  }

  public isAliveAt(): boolean {
    if (this.revokedAt !== null) return false;
    return true;
  }

  public hasOrgBinding(): boolean {
    return this.defaultOrgSlug !== null && this.defaultOrgSlug.length > 0;
  }

  /**
   * Parsed + deduped + trimmed list of OAuth2 scopes this app is
   * allowed to request via the client_credentials grant. Empty
   * when `allowedScopes` is unset / whitespace-only.
   */
  public allowedScopesList(): string[] {
    return parseScopeList(this.allowedScopes);
  }

  /**
   * V1.6: operator-side scope update. Returns a new App with the
   * given scope string. Empty string clears the allowlist (the
   * app can authenticate but receives zero scopes).
   */
  public withAllowedScopes(csv: string): App {
    return new App(
      this.id,
      this.name,
      this.description,
      this.defaultOrgSlug,
      this.contactEmail,
      this.createdAt,
      this.revokedAt,
      this.notes,
      this.currentKey,
      csv.trim(),
      this.idempotencyKey,
    );
  }
}

/**
 * Generate a fresh 32-byte base64url-encoded app API key plaintext.
 * 256 bits of entropy; argon2id-hashed before storage.
 */
export function generateAppApiKeyPlaintext(): string {
  return randomBytes(32).toString('base64url');
}
