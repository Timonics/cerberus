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
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';
import { Argon2AppApiKeyHasher } from '../../infrastructure/security/argon2-app-api-key.hasher';

export interface RegisterAppInput {
  name: string;
  description?: string;
  defaultOrgSlug?: string;
  contactEmail: string;
  notes?: string;
  ttlSeconds: number;
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
  ) {}

  public async execute(input: RegisterAppInput): Promise<RegisterAppResult> {
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
      });
      return this.repo.save(tx, a);
    });

    return { app, plaintextApiKey: plaintextToken };
  }
}
