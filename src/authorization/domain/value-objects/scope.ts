import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * OAuth2 scope value object.
 *
 * Scopes are space-separated tokens in the OAuth2 spec — we model each
 * one as an individual value object so use-cases can build the space-
 * separated string when emitting the access token.
 *
 * Format: lowercase letters, digits, dots, hyphens. Maximum 64 chars.
 *
 * Standard scopes V1 ships:
 *   * `auth:read`       — read own profile, list own sessions
 *   * `auth:write`      — change own password, rotate own sessions
 *   * `auth:admin`      — admin operations on the user level
 *   * `org:admin`       — admin operations within an organization
 *   * `system:admin`    — cross-tenant system operations (V2)
 *
 * Custom scopes are allowed as long as they match the format below.
 */
const SCOPE_RE = /^[a-z][a-z0-9._:-]{0,63}$/;

export class Scope {
  public readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  public static create(raw: string): Scope {
    if (typeof raw !== 'string' || !SCOPE_RE.test(raw)) {
      throw new DomainError(
        'authorization.token.invalid',
        `Invalid scope: ${raw}`,
      );
    }
    return new Scope(raw);
  }

  public static rehydrate(value: string): Scope {
    return new Scope(value);
  }

  public equals(other: Scope): boolean {
    return this.value === other.value;
  }

  public toString(): string {
    return this.value;
  }
}

/**
 * Parse a space-separated scope string (the form RFC 6749 §3.3 uses) into
 * a list of Scope value objects.
 */
export function parseScopes(spaceSeparated: string): ReadonlyArray<Scope> {
  return spaceSeparated
    .split(' ')
    .filter((s) => s.length > 0)
    .map((s) => Scope.create(s));
}

/**
 * Serialize a list of scopes back to the space-separated form for the
 * `scope` claim of an access token.
 */
export function serializeScopes(scopes: ReadonlyArray<Scope>): string {
  return scopes.map((s) => s.value).join(' ');
}
