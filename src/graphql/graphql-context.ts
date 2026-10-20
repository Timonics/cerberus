import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

/**
 * GraphQL request context shape.
 *
 * Populated by `GraphqlContextMiddleware` on every request:
 *   * `authToken` — the raw bearer token (if any), as a string.
 *   * `currentUser` — verified JWT claims (if `authToken` is valid).
 *
 * Resolvers access this via the `@CurrentUser()` decorator.
 */
export interface GraphqlContext {
  readonly req: import('express').Request;
  readonly res: import('express').Response;
  authToken?: string;
  currentUser?: {
    readonly sub: string;
    readonly org: string | null;
    readonly role: string | null;
    readonly scopes: ReadonlyArray<string>;
    readonly jti: string;
    /**
     * V1.7 (audit H-3): the verified token's `typ` claim. Always
     * 'user' (or null for legacy tokens) in practice — app-bound
     * tokens are rejected by `VerifyAccessTokenUseCase` before the
     * context is populated. Guards check this so an app token can
     * never satisfy a user-principal check even if a future caller
     * opts app tokens into context population.
     */
    readonly typ: string | null;
  };
}

/**
 * GraphQL auth verification.
 *
 * Mirrors `JwtAuthGuard` from the Authorization BC, but lives in a
 * context-mutation rather than a Nest guard (guards don't fire on
 * GraphQL resolvers the same way they do on REST routes).
 *
 * Mutates `context.currentUser` in place when a valid `Authorization:
 * Bearer *** header is present. We do NOT throw on missing / invalid
 * tokens — per-resolver decorators decide whether auth is required.
 */
export async function populateGraphqlAuth(
  context: GraphqlContext,
  verifyToken: (token: string) => Promise<{
    sub: string;
    org: string | null;
    role: string | null;
    scopes: ReadonlyArray<string>;
    jti: string;
    typ: string | null;
  }>,
): Promise<void> {
  const header = context.req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return;
  }
  const token = header.substring('Bearer '.length).trim();
  if (!token) {
    return;
  }
  context.authToken = token;
  try {
    const claims = await verifyToken(token);
    context.currentUser = claims;
  } catch {
    // Invalid token — leave currentUser undefined. Resolvers that
    // require auth will throw UNAUTHENTICATED. V1.7 (audit H-3):
    // app-bound tokens (typ: 'app') are rejected by the default
    // VerifyAccessTokenUseCase options, so they never reach the
    // user context either.
  }
}

/**
 * `@CurrentUser()` decorator for GraphQL resolvers.
 *
 * Use:
 *   @Query(() => User)
 *   async me(@CurrentUser() user: GraphqlContext['currentUser']) { ... }
 *
 * Returns the verified user claims, or `undefined` if the request
 * didn't have a valid bearer token.
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const gqlCtx = GqlExecutionContext.create(ctx);
    const context = gqlCtx.getContext<GraphqlContext>();
    return context.currentUser;
  },
);

/**
 * `@IpAddress()` decorator — extracts the request IP.
 */
export const IpAddress = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string | undefined => {
    const gqlCtx = GqlExecutionContext.create(ctx);
    const context = gqlCtx.getContext<GraphqlContext>();
    return context.req.ip ?? context.req.socket?.remoteAddress ?? undefined;
  },
);

/**
 * `@UserAgent()` decorator — extracts the User-Agent header.
 */
export const UserAgent = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string | undefined => {
    const gqlCtx = GqlExecutionContext.create(ctx);
    const context = gqlCtx.getContext<GraphqlContext>();
    return context.req.headers['user-agent'];
  },
);

// (empty — reserved for future jose-specific helpers)
