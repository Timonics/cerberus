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
 * Returns null when no secret was presented at all. Every actual
 * failure mode — unknown app, revoked app, missing / revoked /
 * expired key, wrong secret — throws the SAME
 * `app.credentials.invalid` DomainError. V1.7 (audit): the
 * distinct codes (`app.not_found`, `app.revoked`,
 * `app.api_key.expired`, ...) were a real oracle — a caller could
 * probe app UUIDs and learn which exist and their lifecycle
 * state. The uniform code also matches the client_credentials
 * grant's intentional ambiguity (RFC 6749 §5.2).
 *
 * Ordering matters: the cheap state checks (existence, revoked,
 * expiry) run BEFORE the argon2 verify, so probing with a
 * garbage secret against an expired key costs microseconds, not
 * an argon2id pass.
 *
 * V1: looks the app up directly by id from the header (no scan).
 * V1.5 will index by a separate lookup-token for O(1) verification.
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
      const now = this.clock.now();
      // Cheap checks first (before the argon2 CPU cost), uniform
      // error for every failure mode (no existence/state oracle).
      if (
        !app ||
        app.revokedAt !== null ||
        !app.currentKey ||
        !app.currentKey.isAliveAt(now)
      ) {
        throw new DomainError(
          'app.credentials.invalid',
          'Invalid app credentials',
          { appId: input.appId },
        );
      }
      const ok = await this.hasher.verify(
        app.currentKey.keyHash,
        input.plaintextApiKey,
      );
      if (!ok) {
        throw new DomainError(
          'app.credentials.invalid',
          'Invalid app credentials',
          { appId: input.appId },
        );
      }
      return {
        appId: app.id,
        defaultOrgSlug: app.defaultOrgSlug,
        role: 'APP',
      };
    });
  }
}
