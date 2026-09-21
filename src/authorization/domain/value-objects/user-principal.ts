/**
 * Authenticated principal — extracted from a verified JWT.
 *
 * `userId` is the `sub` claim (a UUID).
 * `organizationSlug` is the `org` claim — null for unscoped tokens
 * (V1 backward-compat) or app-bound tokens whose org has been deleted.
 * `role` is the `role` claim — `OWNER` / `ADMIN` / `MEMBER` / null.
 * `scopes` are the OAuth2 scopes encoded in the `scope` claim,
 * parsed back into a readonly array of strings.
 * `expiresAt` is the `exp` claim — the JwtAuthGuard rejects tokens
 * whose `exp` has passed (jose handles this internally, but we expose
 * it here for downstream use).
 */
export interface UserPrincipal {
  userId: string;
  organizationSlug: string | null;
  role: string | null;
  scopes: ReadonlyArray<string>;
  expiresAt: Date;
}

/**
 * Check whether a principal holds ALL of the required scopes.
 *
 * OAuth2 scope semantics: a token with `auth:read auth:write` satisfies
 * both `auth:read` alone and `auth:write` alone, AND it satisfies the
 * combination `auth:read auth:write`.
 */
export function hasAllScopes(
  principal: UserPrincipal,
  required: ReadonlyArray<string>,
): boolean {
  if (required.length === 0) return true;
  const held = new Set(principal.scopes);
  for (const s of required) {
    if (!held.has(s)) return false;
  }
  return true;
}
