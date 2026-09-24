import { Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { join } from 'node:path';
import { existsSync, readdirSync } from 'node:fs';
import { AppConfig } from '../config/configuration';
import { AuthorizationModule } from '../authorization/authorization.module';
import { GraphqlContext, populateGraphqlAuth } from './graphql-context';
import { VerifyAccessTokenUseCase } from '../authorization/application/use-cases/verify-access-token.use-case';
import { GraphqlDomainErrorFilter } from './graphql-domain-error.filter';

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
 * context. Resolvers access claims via `@CurrentUser()`.
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
