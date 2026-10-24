import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  CLOCK,
  Clock,
  DomainError,
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
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';
import { assertAppScopes } from '../../domain/value-objects/app-scope';

export interface RegisterAppInput {
  name: string;
  description?: string;
  /**
   * Optional, but when provided it MUST resolve to an existing
   * organization — app creation rejects unknown slugs instead of
   * silently storing a dangling binding (which used to degrade to
   * personal-org registration at user-register time, invisibly).
   */
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
  /**
   * Optional idempotency key (`Idempotency-Key` header on REST,
   * input field on GraphQL). When present:
   *   * First call with a given key → creates the app normally.
   *   * Retry with the same key → returns the ORIGINAL app with
   *     `plaintextApiKey: null` (the key is never re-issued), so a
   *     timed-out or double-submitted request can't mint duplicates.
   *   * The app bound to a key was revoked → 400, the key is
   *     considered consumed (never silently rebinds a dead app).
   * Concurrent same-key requests race on the unique index; the
   * loser transparently becomes a replay.
   */
  idempotencyKey?: string;
}

export interface RegisterAppResult {
  app: App;
  /**
   * Plaintext API key — returned ONCE, never retrievable. NULL on
   * an idempotent replay (the original response already carried it).
   */
  plaintextApiKey: string | null;
}

/**
 * Register a new third-party application.
 *
 * Open to unauthenticated callers (like `/v1/identity/register`). Returns
 * the app aggregate + a freshly-minted API key plaintext. The plaintext
 * is shown to the developer exactly once.
 *
 * If `defaultOrgSlug` is supplied, users registered with this app's
 * `X-Cerberus-App-Id` header will be auto-bound to that org. The slug
 * is validated HERE — an unknown slug rejects the whole app creation
 * with `domain.invariant_violation` rather than being stored and
 * silently degrading to personal-org registration later (the
 * registration use-case's Path 2 falls through when the org row is
 * missing, so a dangling binding never surfaces until a user
 * registers). If omitted, the app can still authenticate (its key
 * works for future `/v1/apps/*` calls) but users fall through to
 * personal-org auto-creation.
 */
@Injectable()
export class RegisterAppUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(APP_REPOSITORY) private readonly repo: AppRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
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

    // Idempotency: normalize + validate the key BEFORE the argon2
    // hash so a garbage key costs microseconds, not an argon2id pass.
    const idempotencyKey = input.idempotencyKey?.trim() || null;
    if (idempotencyKey && idempotencyKey.length > 128) {
      throw new DomainError(
        'app.idempotency_key.invalid',
        'Idempotency key must be at most 128 characters',
      );
    }
    if (idempotencyKey) {
      const existing = await this.txRunner.run<App | null>((tx: Tx) =>
        this.repo.findByIdempotencyKey(tx, idempotencyKey),
      );
      if (existing) {
        if (existing.revokedAt !== null) {
          // The key is bound to a dead app — never silently rebind
          // it; force the caller to mint a fresh key.
          throw new DomainError(
            'app.idempotency_key.invalid',
            'Idempotency key was consumed by a revoked app; use a new key',
            { appId: existing.id },
          );
        }
        // Replay: same app, no key re-issue.
        return { app: existing, plaintextApiKey: null };
      }
    }

    const plaintextToken = generateAppApiKeyPlaintext();
    const keyHash = await this.hasher.hash(plaintextToken);

    const app = await this.txRunner
      .run<App | { replayed: App }>(async (tx: Tx) => {
        // Validate the org binding BEFORE persisting anything: a
        // dangling slug used to store fine and only degrade to
        // personal-org registration at user-register time (see the
        // module doc comment). Fail loud at creation instead.
        if (input.defaultOrgSlug) {
          const slug = OrgSlug.create(input.defaultOrgSlug);
          if (!(await this.organizationRepo.findBySlug(tx, slug))) {
            throw new DomainError(
              'domain.invariant_violation',
              'No organization with that slug exists',
              { slug: slug.value },
            );
          }
        }

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
          idempotencyKey,
        });
        return this.repo.save(tx, a);
      })
      .catch((err: unknown) => {
        // Two same-key requests racing both pass the pre-check; the
        // unique index makes the loser lose HERE. Convert the P2002
        // into a replay instead of a 500 (same treatment as the
        // registration use-case's email-unique race). The wrapper
        // marks the result so the plaintext of OUR key — which was
        // never persisted — is not handed out for the winner's app.
        if (
          err instanceof Prisma.PrismaClientKnownRequestError &&
          err.code === 'P2002' &&
          idempotencyKey
        ) {
          return this.txRunner
            .run<App | null>((tx: Tx) =>
              this.repo.findByIdempotencyKey(tx, idempotencyKey),
            )
            .then((replayed) => {
              // The winner's row vanished mid-race (not expected in
              // practice — rows are only ever soft-revoked) — surface
              // the original constraint error rather than a replay.
              if (!replayed) throw err;
              return { replayed };
            });
        }
        throw err;
      });

    const isReplay = app !== null && 'replayed' in app;
    const created = isReplay ? app.replayed : app;

    // Audit: apps.app.registered. V1 doesn't bind apps to a user, so
    // userId is null — admin audit search by event type still works.
    // Replays don't re-audit: the original registration already did.
    if (!isReplay) {
      await this.recordAuditEventUc.execute({
        userId: null,
        eventType: 'apps.app.registered',
        payload: {
          appId: created.id,
          name: created.name,
          defaultOrgSlug: created.defaultOrgSlug,
          allowedScopes: created.allowedScopes,
        },
      });
    }

    return {
      app: created,
      plaintextApiKey: isReplay ? null : plaintextToken,
    };
  }
}
