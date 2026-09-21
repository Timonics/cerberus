import { Args, Int, Mutation, Resolver } from '@nestjs/graphql';
import { Public } from '../../../authorization/interfaces/security/public.decorator';
import { RegisterAppUseCase } from '../../application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from '../../application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from '../../application/use-cases/revoke-app.use-case';
import { App } from '../../domain/aggregates/app';

/**
 * GraphQL resolver for the Apps BC.
 *
 * V1.5 mirrors the REST /v1/apps surface. The mutation methods are
 * `@Public()` because V1 lets anyone mint an app anonymously — same
 * as the REST endpoint. The use-cases are the same ones the REST
 * controller calls, so audit logging + IP allowlist behavior is
 * identical.
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
  ) {}

  /**
   * `registerApp(input)` — see apps.graphql.
   *
   * Returns the App aggregate + plaintext API key (one-time).
   */
  @Public()
  @Mutation(() => 'RegisterAppPayload', {
    description:
      'Register a new third-party application + mint its first API key. Returns the plaintext key exactly once.',
  })
  public async registerApp(
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
   */
  @Public()
  @Mutation(() => 'RotateAppKeyPayload', {
    description:
      'Mint a new API key for an existing app. Old key keeps working until revokeApp is called.',
  })
  public async rotateAppKey(
    @Args('id') id: string,
    @Args('ttlSeconds', { type: () => Int, nullable: true })
    ttlSeconds?: number,
  ): Promise<{ appId: string; apiKey: string }> {
    const { app, plaintextApiKey } = await this.rotateKeyUc.execute(
      id,
      ttlSeconds ?? 31536000,
    );
    return { appId: app.id, apiKey: plaintextApiKey };
  }

  /**
   * `revokeApp(id)` — see apps.graphql.
   */
  @Public()
  @Mutation(() => 'Boolean', {
    description: 'Soft-revoke the app. Idempotent.',
  })
  public async revokeApp(@Args('id') id: string): Promise<boolean> {
    await this.revokeAppUc.execute(id);
    return true;
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
