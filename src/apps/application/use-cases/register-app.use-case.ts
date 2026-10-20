import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { App, generateAppApiKeyPlaintext } from '../../domain/aggregates/app';
import { AppApiKey } from '../../domain/aggregates/app-api-key';
import { Argon2AppApiKeyHasher } from '../../infrastructure/security/argon2-app-api-key.hasher';
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { assertAppScopes } from '../../domain/value-objects/app-scope';

export interface RegisterAppInput {
  name: string;
  description?: string;
  defaultOrgSlug?: string;
  contactEmail: string;
  notes?: string;
  ttlSeconds: number;
  /**
   * V1.6 client_credentials grant: initial OAuth2 scope allowlist.
   * V1.7 (audit H-3): validated against the server-side app-scope
   * registry — unknown scopes are rejected with `app.scope.invalid`.
   * Apps can never hold user scopes (`org:admin`, `introspect:read`,
   * `auth:read`, `auth:write`).
   */
  initialScopes?: string;
}

export interface RegisterAppResult {
  app: App;
  /** Plaintext API key — returned ONCE, never retrievable. */
  plaintextApiKey: string;
}

/**
 * Register a new third-party application.
 *
 * Open to unauthenticated callers (like `/v1/identity/register`). Returns
 * the app aggregate + a freshly-minted API key plaintext. The plaintext
 * is shown to the developer exactly once.
 *
 * If `defaultOrgSlug` is supplied, users registered with this app's
 * `X-Cerberus-App-Id` header will be auto-bound to that org. If omitted,
 * the app can still authenticate (its key works for future `/v1/apps/*`
 * calls) but users fall through to email-domain matching or personal-org
 * auto-creation.
 */
@Injectable()
export class RegisterAppUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(APP_REPOSITORY) private readonly repo: AppRepository,
    private readonly hasher: Argon2AppApiKeyHasher,
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(input: RegisterAppInput): Promise<RegisterAppResult> {
    // V1.7 (audit H-3): validate the requested scopes against the
    // server-side app-scope registry BEFORE anything is persisted.
    // Unknown scopes are rejected (not silently dropped) so a typo
    // can't leave the operator believing a scope was granted.
    const validatedScopes =
      input.initialScopes !== undefined
        ? assertAppScopes(input.initialScopes).join(',')
        : undefined;

    const plaintextToken = generateAppApiKeyPlaintext();
    const keyHash = await this.hasher.hash(plaintextToken);

    const app = await this.txRunner.run<App>(async (tx: Tx) => {
      const appId = this.idGenerator.generate();
      const keyId = this.idGenerator.generate();
      const initialKey = AppApiKey.issue({
        id: keyId,
        appId,
        plaintextToken,
        keyHash,
        name: `${input.name} initial key`,
        clock: this.clock,
        ttlSeconds: input.ttlSeconds,
      });
      const a = App.register({
        id: appId,
        name: input.name,
        description: input.description ?? null,
        defaultOrgSlug: input.defaultOrgSlug ?? null,
        contactEmail: input.contactEmail,
        clock: this.clock,
        notes: input.notes,
        initialKey,
        allowedScopes: validatedScopes,
      });
      return this.repo.save(tx, a);
    });

    // Audit: apps.app.registered. V1 doesn't bind apps to a user, so
    // userId is null — admin audit search by event type still works.
    await this.recordAuditEventUc.execute({
      userId: null,
      eventType: 'apps.app.registered',
      payload: {
        appId: app.id,
        name: app.name,
        defaultOrgSlug: app.defaultOrgSlug,
        allowedScopes: app.allowedScopes,
      },
    });

    return { app, plaintextApiKey: plaintextToken };
  }
}
