import { ExecutionContext } from '@nestjs/common';
import { Args, Context, Int, Mutation, Resolver } from '@nestjs/graphql';
import { RegisterAppUseCase } from '../../application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from '../../application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from '../../application/use-cases/revoke-app.use-case';
import { VerifyAppApiKeyUseCase } from '../../application/use-cases/verify-app-api-key.use-case';
import { ProductionAdminGuard } from '../../../common/security/production-admin.guard';
import { GraphqlContext } from '../../../graphql/graphql-context';
import { GqlForbiddenException } from '../../../graphql/graphql-errors';
import { App } from '../../domain/aggregates/app';

/**
 * GraphQL resolver for the Apps BC.
 *
 * V1.7 (audits C2 / H-1): the GraphQL surface now enforces the SAME
 * auth rules as the REST `/v1/apps` controller — previously these
 * mutations were effectively unauthenticated because `@Public()` is
 * REST metadata that no GraphQL guard reads:
 *
 *   * `registerApp` — behind the same `ProductionAdminGuard` as
 *     `POST /v1/apps`: open in dev/staging, requires a valid admin
 *     API key bearer token in production (or always, when
 *     `REQUIRE_ADMIN_FOR_REGISTRATION=true`).
 *   * `rotateAppKey` / `revokeApp` — require the app's CURRENT
 *     credentials (`X-Cerberus-App-Id` + `X-Cerberus-App-Secret`
 *     headers, verified via `VerifyAppApiKeyUseCase`), and the app
 *     id in the mutation must equal the authenticated app id. Only
 *     the app itself can rotate its key or revoke itself.
 *
 * The use-cases are the same ones the REST controller calls, so
 * audit logging behavior is identical.
 *
 * The `App` GraphQL type is defined inline via `@nestjs/graphql`'s
 * `info` decorators (we use string type names to avoid generating
 * GraphQL SDL classes — the SDL files are the source of truth).
 */
@Resolver(() => 'Mutation')
export class AppsGraphqlResolver {
  public constructor(
    private readonly registerAppUc: RegisterAppUseCase,
    private readonly rotateKeyUc: RotateAppApiKeyUseCase,
    private readonly revokeAppUc: RevokeAppUseCase,
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
    private readonly productionAdminGuard: ProductionAdminGuard,
  ) {}

  /**
   * `registerApp(input)` — see apps.graphql.
   *
   * Returns the App aggregate + plaintext API key (one-time).
   */
  @Mutation(() => 'RegisterAppPayload', {
    description:
      'Register a new third-party application + mint its first API key. Returns the plaintext key exactly once. Requires a valid admin API key bearer token in production (mirrors REST /v1/apps); open in non-production.',
  })
  public async registerApp(
    @Context() gqlContext: GraphqlContext,
    @Args('input')
    input: {
      name: string;
      description?: string;
      defaultOrgSlug?: string;
      contactEmail?: string;
      notes?: string;
      ttlSeconds?: number;
    },
  ): Promise<{ app: any; apiKey: string }> {
    // V1.7 (audit H-1): reuse the REST ProductionAdminGuard so the
    // GraphQL path can never drift from the REST gate. The guard
    // only needs the underlying express request; we hand it a
    // minimal ExecutionContext shim around it.
    await this.productionAdminGuard.canActivate({
      switchToHttp: () => ({
        getRequest: () => gqlContext.req,
      }),
    } as ExecutionContext);
    const { app, plaintextApiKey } = await this.registerAppUc.execute({
      name: input.name,
      description: input.description ?? undefined,
      defaultOrgSlug: input.defaultOrgSlug ?? undefined,
      contactEmail: input.contactEmail ?? '',
      notes: input.notes ?? undefined,
      ttlSeconds: input.ttlSeconds ?? 31536000,
    });
    return { app: this.toGraphql(app), apiKey: plaintextApiKey };
  }

  /**
   * `rotateAppKey(id, ttlSeconds)` — see apps.graphql.
   *
   * V1.7 (audit C2): requires the app's current credentials; the
   * mutation's `id` must equal the `X-Cerberus-App-Id` header.
   */
  @Mutation(() => 'RotateAppKeyPayload', {
    description:
      "Mint a new API key for an existing app. Requires the app's current credentials (X-Cerberus-App-Id + X-Cerberus-App-Secret headers); the mutation id must match the authenticated app id. Old key keeps working until revokeApp is called.",
  })
  public async rotateAppKey(
    @Context() gqlContext: GraphqlContext,
    @Args('id') id: string,
    @Args('ttlSeconds', { type: () => Int, nullable: true })
    ttlSeconds?: number,
  ): Promise<{ appId: string; apiKey: string }> {
    await this.requireOwnCurrentKey(id, gqlContext);
    const { app, plaintextApiKey } = await this.rotateKeyUc.execute(
      id,
      ttlSeconds ?? 31536000,
    );
    return { appId: app.id, apiKey: plaintextApiKey };
  }

  /**
   * `revokeApp(id)` — see apps.graphql.
   *
   * V1.7 (audit C2): same credential requirement as rotateAppKey —
   * without it this was an unauthenticated DoS against any app.
   */
  @Mutation(() => 'Boolean', {
    description:
      "Soft-revoke the app. Idempotent. Requires the app's current credentials (X-Cerberus-App-Id + X-Cerberus-App-Secret headers); the mutation id must match the authenticated app id.",
  })
  public async revokeApp(
    @Context() gqlContext: GraphqlContext,
    @Args('id') id: string,
  ): Promise<boolean> {
    await this.requireOwnCurrentKey(id, gqlContext);
    await this.revokeAppUc.execute(id);
    return true;
  }

  /**
   * Verify the caller's current app credentials before allowing a
   * rotate-key or revoke operation. Mirrors the REST controller's
   * `requireOwnCurrentKey` (audit C2): the mutation id must match
   * the `X-Cerberus-App-Id` header, and the secret must verify
   * against the app's current key. Every failure mode collapses
   * into FORBIDDEN so the endpoint can't be used as an
   * app-existence oracle.
   */
  private async requireOwnCurrentKey(
    id: string,
    gqlContext: GraphqlContext,
  ): Promise<void> {
    const headers = gqlContext.req.headers;
    const headerAppId = headers['x-cerberus-app-id'];
    const headerAppSecret = headers['x-cerberus-app-secret'];
    if (
      typeof headerAppId !== 'string' ||
      typeof headerAppSecret !== 'string' ||
      !headerAppId.trim() ||
      !headerAppSecret.trim()
    ) {
      throw new GqlForbiddenException(
        'X-Cerberus-App-Id and X-Cerberus-App-Secret headers required',
      );
    }
    if (id !== headerAppId.trim()) {
      throw new GqlForbiddenException(
        'App ID in mutation does not match X-Cerberus-App-Id header',
      );
    }
    try {
      const verified = await this.verifyAppApiKeyUc.execute({
        appId: headerAppId.trim(),
        plaintextApiKey: headerAppSecret.trim(),
      });
      if (!verified || verified.appId !== id) {
        throw new GqlForbiddenException('Invalid current app credentials');
      }
    } catch (err) {
      if (err instanceof GqlForbiddenException) throw err;
      throw new GqlForbiddenException('Invalid current app credentials');
    }
  }

  /** Convert the App aggregate to the GraphQL DTO shape. */
  private toGraphql(app: App): unknown {
    return {
      id: app.id,
      name: app.name,
      description: app.description,
      defaultOrgSlug: app.defaultOrgSlug,
      contactEmail: app.contactEmail,
      notes: app.notes,
      createdAt: app.createdAt.toISOString(),
      revokedAt: app.revokedAt ? app.revokedAt.toISOString() : null,
    };
  }
}
