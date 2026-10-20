import { DomainError } from '../../../shared/domain';

/**
 * Server-side registry of the OAuth2 scopes an App may hold.
 *
 * V1.7 (audit H-3): `initialScopes` used to be free text — a registered
 * app could persist `org:admin` (or any other user-scope) and then
 * self-grant it via the client_credentials grant, because token
 * issuance only intersected against the app's own stored allowlist.
 * The registry breaks that chain: scopes are validated against this
 * fixed enum at registration, and every read path filters through
 * it, so a stored row can never smuggle a user-scope into an app
 * token even if it was written by an older version.
 *
 * App tokens exist for service-to-service calls. Deliberately NOT in
 * the registry (they stay user-only): `org:admin`, `introspect:read`,
 * `auth:read`, `auth:write`.
 */
export const APP_SCOPES = ['app:register', 'app:auth', 'app:read'] as const;

export type AppScope = (typeof APP_SCOPES)[number];

const APP_SCOPE_SET: ReadonlySet<string> = new Set<string>(APP_SCOPES);

/** True when the value is one of the scopes an App may hold. */
export function isAppScope(value: string): boolean {
  return APP_SCOPE_SET.has(value);
}

/**
 * Intersect a caller-supplied scope list with the registry:
 * trim, drop empties, drop anything not in the registry, dedupe.
 * Used on every read path (`App.allowedScopesList`, the
 * client_credentials scope downgrade) so persisted garbage can
 * never widen what a token gets.
 */
export function filterAppScopes(scopes: ReadonlyArray<string>): string[] {
  return Array.from(
    new Set(
      scopes
        .map((s) => s.trim())
        .filter((s) => s.length > 0 && APP_SCOPE_SET.has(s)),
    ),
  );
}

/**
 * Validate a caller-supplied (comma-separated) scope list at the
 * registration boundary. Throws `app.scope.invalid` naming the
 * unknown scopes — registration must REJECT rather than silently
 * drop, so a typo (`app:reads`) doesn't leave the operator
 * believing a scope was granted.
 */
export function assertAppScopes(csv: string): string[] {
  const requested = Array.from(
    new Set(
      csv
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    ),
  );
  const unknown = requested.filter((s) => !APP_SCOPE_SET.has(s));
  if (unknown.length > 0) {
    throw new DomainError(
      'app.scope.invalid',
      'Unknown app scope(s). Allowed: ' + APP_SCOPES.join(', '),
      { unknownScopes: unknown },
    );
  }
  return requested;
}
