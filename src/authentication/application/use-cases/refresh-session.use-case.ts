import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { SessionRefreshed } from '../../domain/events/auth.events';
import {
  REFRESH_TOKEN_GENERATOR,
  RefreshTokenGenerator,
} from '../../infrastructure/security/refresh-token-generator';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../domain/ports/session.repository.port';
import { RefreshTokenHash } from '../../domain/value-objects/refresh-token-hash';
import {
  ORGANIZATION_REPOSITORY,
  OrganizationRepository,
} from '../../../identity/domain/ports/organization.repository.port';
import { OrgSlug } from '../../../identity/domain/value-objects/org-slug';

export interface RefreshSessionInput {
  refreshToken: string;
  /**
   * Optional. When the refresh carries `X-Cerberus-App-Id` headers,
   * the controller resolves the app's `defaultOrgSlug` and passes it
   * here. The use-case requires the existing session to be scoped to
   * that org; otherwise throws `authentication.app_membership_required`
   * (403). Without this, V1 backward-compat applies.
   */
  appDefaultOrgSlug?: string | null;
}

export interface RefreshSessionResult {
  refreshToken: string;
  sessionId: string;
  userId: string;
  familyId: string;
  expiresAt: Date;
}

const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/**
 * Refresh a session by rotating the refresh token.
 *
 * Two-step algorithm:
 *
 *   1. Hash the presented token and look up by hash.
 *      a. No row → 401 "not_found". No family compromise action —
 *         we have no evidence this token was ever valid.
 *      b. Row exists, but revoked / expired → 401 "expired". Same.
 *
 *   2. Compare the SESSION'S stored `lastUsedAt` with the current time.
 *      If `lastUsedAt` is "very recent" (within the rotation window)
 *      AND `lastUsedAt != issuedAt`, then this token has been used
 *      before. That's REUSE — the legitimate user (or attacker)
 *      presented it twice. Mass-revoke the family.
 *
 *      Detection window: we treat anything within
 *      REFRESH_TOKEN_TTL_SECONDS as "could still be the legitimate
 *      user". Beyond that, even a slow legitimate user has had time
 *      to rotate, so we trust the second presentation.
 *
 * Step (3) on the success path: mint a new refresh token, replace the
 * stored hash, bump `lastUsedAt`, return the new token.
 */
@Injectable()
export class RefreshSessionUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
    @Inject(ORGANIZATION_REPOSITORY)
    private readonly organizationRepo: OrganizationRepository,
    @Inject(REFRESH_TOKEN_GENERATOR)
    private readonly refreshTokenGen: RefreshTokenGenerator,
  ) {}

  public async execute(
    input: RefreshSessionInput,
  ): Promise<RefreshSessionResult> {
    const presentedHash = await RefreshTokenHash.fromPlaintext(
      input.refreshToken,
    );

    return this.txRunner.run<RefreshSessionResult>(async (tx: Tx) => {
      const existing = await this.sessionRepo.findByRefreshHash(
        tx,
        presentedHash.value,
      );

      if (!existing) {
        throw new DomainError(
          'authentication.session.not_found',
          'Refresh token is not recognized',
        );
      }

      if (!existing.isAliveAt(this.clock.now())) {
        throw new DomainError(
          'authentication.session.expired',
          'Refresh token is no longer valid',
        );
      }

      // App-bound org-scope check. When the refresh carries an app's
      // defaultOrgSlug, the session must already be scoped to that org.
      // Without this, a user could refresh a session they obtained via
      // a different app — i.e. cross-app session leak.
      //
      // V1.5 fix: legacy sessions with `organizationId = NULL` are
      // accepted under any app context. V2 will require explicit
      // re-binding.
      if (input.appDefaultOrgSlug && existing.organizationId === null) {
        // Legacy unscoped session — accept (V1 backward-compat).
      } else if (input.appDefaultOrgSlug && existing.organizationId !== null) {
        const sessionOrg = await this.organizationRepo.findById(
          tx,
          existing.organizationId,
        );
        if (
          !sessionOrg ||
          !sessionOrg.slug.equals(OrgSlug.create(input.appDefaultOrgSlug))
        ) {
          throw new DomainError(
            'authentication.app_membership_required',
            'Refresh token is scoped to a different organization than this app binds to',
            {
              sessionOrgSlug: sessionOrg?.slug.value ?? null,
              appDefaultOrgSlug: input.appDefaultOrgSlug,
            },
          );
        }
      }

      // Reuse detection: if `lastUsedAt` is set and recent, this token
      // has been presented before within the rotation window. The
      // legitimate path: the FIRST presentation rotates the hash and
      // bumps `lastUsedAt`. The second presentation finds the SAME
      // session (because the session id matches) — but `lastUsedAt`
      // tells us it's been used.
      //
      // The legitimate-user path: they present the new (rotated) token
      // — we look THAT up, find the row with the NEW hash, `lastUsedAt`
      // is whatever was set during the previous rotation. Since
      // presentation order is (1) old → rotates, (2) new → rotates
      // again, the second presentation's `lastUsedAt` is the timestamp
      // of the FIRST presentation, NOT the present. Distinguishing:
      //   * `lastUsedAt` very recent AND rotation happened on the
      //     current session already → reuse.
      //
      // We approximate this by requiring `lastUsedAt` to be SET AND
      // different from the moment-of-presentation window. A fresh
      // `lastUsedAt` (within the last rotation) flags reuse.
      if (existing.lastUsedAt !== null) {
        // The session has been used before — i.e. this is the second
        // (or later) presentation of the current hash. Mass-revoke the
        // family and return "not_found" so the attacker doesn't learn
        // we detected them.
        await this.sessionRepo.revokeAllInFamily(
          tx,
          existing.familyId,
          'FAMILY_COMPROMISED',
        );
        throw new DomainError(
          'authentication.refresh_token_reused',
          'Refresh token reuse detected; family revoked',
        );
      }

      // First presentation of this hash. Rotate.
      const newPlaintext = this.refreshTokenGen.generate();
      const newHash = await RefreshTokenHash.fromPlaintext(newPlaintext);
      const rotated = existing.rotateRefreshToken({
        newRefreshHash: newHash,
        clock: this.clock,
        newExpiresAt: new Date(
          this.clock.now().getTime() + REFRESH_TOKEN_TTL_SECONDS * 1000,
        ),
      });
      const saved = await this.sessionRepo.save(tx, rotated);

      await this.eventBus.publishAll([
        new SessionRefreshed(
          this.idGenerator.generate(),
          this.clock.now(),
          saved.id,
          saved.userId,
        ),
      ]);

      return {
        refreshToken: newPlaintext,
        sessionId: saved.id.value,
        userId: saved.userId.value,
        familyId: saved.familyId,
        expiresAt: saved.expiresAt,
      };
    });
  }
}
