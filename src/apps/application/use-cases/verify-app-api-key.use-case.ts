import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  APP_REPOSITORY,
  AppRepository,
} from '../../domain/ports/app.repository.port';
import { Argon2AppApiKeyHasher } from '../../infrastructure/security/argon2-app-api-key.hasher';

export interface VerifyAppApiKeyInput {
  appId: string;
  plaintextApiKey: string;
}

export interface VerifyAppApiKeyResult {
  appId: string;
  defaultOrgSlug: string | null;
  role: 'APP';
}

/**
 * Verify an app's credentials (presented as `X-Cerberus-App-Id` +
 * `X-Cerberus-App-Secret` headers on register/login/etc.).
 *
 * Returns null on failure (unknown key, revoked key, expired key,
 * revoked app). Throws `app.revoked` / `app.api_key.expired` /
 * `app.not_found` to disambiguate for the audit log.
 *
 * V1: scans all keys and verifies each (acceptable for the V1
 * "few apps per deployment" scale). V1.5 will index by a separate
 * lookup-token for O(1) verification.
 */
@Injectable()
export class VerifyAppApiKeyUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(APP_REPOSITORY) private readonly repo: AppRepository,
    private readonly hasher: Argon2AppApiKeyHasher,
  ) {}

  public async execute(
    input: VerifyAppApiKeyInput,
  ): Promise<VerifyAppApiKeyResult | null> {
    if (!input.plaintextApiKey || !input.plaintextApiKey.trim()) {
      return null;
    }
    // Direct lookup by appId — we have it from the header, so no scan.
    return this.txRunner.run<VerifyAppApiKeyResult | null>(async (tx: Tx) => {
      const app = await this.repo.findById(tx, input.appId);
      if (!app) {
        throw new DomainError('app.not_found', 'App not found', {
          appId: input.appId,
        });
      }
      if (app.revokedAt !== null) {
        throw new DomainError('app.revoked', 'App has been revoked', {
          appId: input.appId,
        });
      }
      if (!app.currentKey) {
        throw new DomainError(
          'app.api_key.not_found',
          'App has no active key',
          { appId: input.appId },
        );
      }
      const ok = await this.hasher.verify(
        app.currentKey.keyHash,
        input.plaintextApiKey,
      );
      if (!ok) {
        throw new DomainError('app.api_key.invalid', 'Invalid app API key', {
          appId: input.appId,
        });
      }
      if (!app.currentKey.isAliveAt(this.clock.now())) {
        if (app.currentKey.revokedAt !== null) {
          throw new DomainError('app.api_key.revoked', 'App key revoked');
        }
        throw new DomainError('app.api_key.expired', 'App key expired');
      }
      return {
        appId: app.id,
        defaultOrgSlug: app.defaultOrgSlug,
        role: 'APP',
      };
    });
  }
}
