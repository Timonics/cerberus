import { Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { APP_GUARD } from '@nestjs/core';
import { join } from 'node:path';
import { existsSync, readdirSync } from 'node:fs';
import { AppConfig } from '../config/configuration';
import { AuthorizationModule } from '../authorization/authorization.module';
import { GraphqlContext, populateGraphqlAuth } from './graphql-context';
import { VerifyAccessTokenUseCase } from '../authorization/application/use-cases/verify-access-token.use-case';
import { GraphqlDomainErrorFilter } from './graphql-domain-error.filter';
import { GraphqlThrottleGuard } from './guards/graphql-throttle.guard';
import { createFieldCountLimitRule } from './validation/field-count-limit.rule';

/**
 * GraphQL module.
 *
 * Mounted at `/graphql`. Schema-first: SDL files live alongside
 * resolvers under `<bc>/interfaces/graphql/schema.graphql`. Auto-
 * loaded by `GraphQLModule` via the configured `typePaths`.
 *
 * Auth: every request runs through `populateGraphqlAuth`, which
 * extracts the bearer token, verifies it (via the same path as the
 * REST `JwtAuthGuard`), and attaches the decoded claims to the
 * context. Resolvers access claims via `@CurrentUser()`. App-bound
 * tokens (`typ: 'app'`) are rejected by that verification and can
 * never populate the user context.
 *
 * Rate limiting: `GraphqlThrottleGuard` is registered as a global
 * guard (audit H-6) — per-IP + per-email Redis counters covering
 * every operation, mirroring the REST `ThrottleGuard` caps.
 *
 * Query-size cap: `createFieldCountLimitRule` limits each operation
 * to 100 field selections (aliases count individually; introspection
 * meta-fields excluded) to blunt alias-batching DoS.
 *
 * The SDL `typePaths` probe (see `resolveTypePaths`) is what makes
 * the module robust to `build:clean` — without it, wiping `dist/`
 * would crash the bootstrap because the copied SDL files would also
 * disappear, even though the source SDL is still intact.
 */
@Module({
  imports: [
    AuthorizationModule,
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      imports: [ConfigModule],
      inject: [ConfigService, VerifyAccessTokenUseCase],
      useFactory: (
        config: ConfigService,
        verifyToken: VerifyAccessTokenUseCase,
      ) => {
        const introspectionEnabled =
          config.getOrThrow<AppConfig['graphql']>(
            'graphql',
          ).introspectionEnabled;
        const playgroundEnabled =
          config.getOrThrow<AppConfig['graphql']>('graphql').playgroundEnabled;

        const typePaths = resolveTypePaths();

        return {
          typePaths,
          sortSchema: true,
          playground: playgroundEnabled,
          introspection: introspectionEnabled,
          plugins: [],
          // V1.7 (audit, GraphQL MEDIUM): cap the total field count
          // per operation (aliases included) to blunt alias-batching
          // DoS — N aliased selections used to mean N sequential
          // resolver round-trips inside one HTTP request.
          validationRules: [createFieldCountLimitRule()],
          // V1.5 (audit L-5): register the GqlExceptionFilter for
          // DomainError so resolvers' errors surface with stable
          // extensions.code (and .domainCode). Without this,
          // Apollo's default handler wraps uncaught errors in
          // INTERNAL_SERVER_ERROR and the domainCode is lost.
          filters: [new GraphqlDomainErrorFilter()],
          context: async ({
            req,
            res,
          }: {
            req: import('express').Request;
            res: import('express').Response;
          }): Promise<GraphqlContext> => {
            const ctx: GraphqlContext = { req, res };
            await populateGraphqlAuth(ctx, async (token) => {
              const claims = await verifyToken.execute(token);
              return {
                sub: claims.subject,
                org: claims.organizationId,
                role: claims.role,
                scopes: claims.scopes,
                jti: claims.jti,
                typ: claims.tokenType,
              };
            });
            return ctx;
          },
          formatError: (formattedError) => {
            // The GraphqlDomainErrorFilter sets extensions.code to a
            // GraphQL-shaped string (FORBIDDEN, UNAUTHENTICATED, etc.)
            // AND extensions.domainCode to the raw DomainError code.
            //
            // We prefer the filter's classification if present; only
            // fall back to the raw domainCode when the filter
            // somehow didn't run (defensive — e.g. a thrown error
            // that's not a DomainError).
            const extensions = formattedError.extensions as
              | {
                  domainCode?: string;
                  code?: string;
                }
              | undefined;
            const filterCode = extensions?.code;
            const domainCode = extensions?.domainCode;
            if (filterCode) {
              // Filter ran — leave extensions.code as-is.
              return formattedError;
            }
            if (domainCode) {
              return {
                ...formattedError,
                extensions: {
                  ...formattedError.extensions,
                  code: domainCode,
                },
              };
            }
            return formattedError;
          },
        };
      },
    }),
  ],
  exports: [GraphQLModule],
  providers: [
    // V1.7 (audit H-6): global GraphQL rate limiting. Registered
    // as an APP_GUARD so every field resolution (public queries
    // and mutations alike) passes through it; the guard no-ops on
    // non-GraphQL contexts. RedisService resolves from the global
    // RedisModule.
    {
      provide: APP_GUARD,
      useClass: GraphqlThrottleGuard,
    },
  ],
})
export class GraphqlModule implements NestModule {
  public configure(): void {
    // No-op. We could add express middleware here for body parsing,
    // but Apollo handles its own routing at /graphql.
  }
}

/**
 * Resolve the GraphQL SDL file glob.
 *
 * Two candidate roots are checked at module-init time, in priority
 * order:
 *   1. `dist/graphql/types/` — produced by `npm run build` (which
 *      runs `scripts/copy-graphql-sdl.js`). This is the layout used
 *      in production (`node dist/main.js`).
 *   2. `src/graphql/types/` — the source layout. Used when running
 *      directly from source (`nest start`, `nest start --watch`).
 *
 * The first candidate that contains at least one `.graphql` file
 * wins. If neither does, we throw a clear error pointing the
 * operator at `npm run build`.
 *
 * Why this exists: `npm run build:clean` wipes `dist/` entirely.
 * The old code unconditionally pointed at `dist/graphql/types/`,
 * which made a freshly-cleaned checkout crash the bootstrap with
 * "no type definitions found" — even though the source SDL was
 * still intact.
 */
function resolveTypePaths(): string[] {
  const candidates = [
    join(__dirname, '../graphql/types/**/*.graphql'),
    join(process.cwd(), 'src/graphql/types/**/*.graphql'),
  ];
  const found = candidates.filter((pattern) => {
    const dir = pattern.split('*')[0];
    if (!existsSync(dir)) return false;
    try {
      return readdirSync(dir).some((f) => f.endsWith('.graphql'));
    } catch {
      return false;
    }
  });
  if (found.length === 0) {
    throw new Error(
      `Could not find any .graphql SDL files under any of: ${candidates.join(', ')}. ` +
        'Run `npm run build` (it copies the SDL files into dist/graphql/types/).',
    );
  }
  return found;
}
