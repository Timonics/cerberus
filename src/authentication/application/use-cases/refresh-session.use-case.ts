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
import { Session } from '../../domain/aggregates/session';
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

      // Reuse detection (V1.5): reuse means the presented hash was
      // previously rotated OUT (i.e. it's in `previousRefreshHashes`).
      //
      // The legitimate path:
      //   (1) user presents OLD hash → it's in `refreshHash` →
      //       we rotate → OLD hash moves to `previousRefreshHashes`,
      //       NEW hash becomes `refreshHash`.
      //   (2) user presents NEW hash → it's in `refreshHash` → rotate again.
      //
      // The illegitimate path (an attacker captured an OLD token after
      // the legitimate user already rotated):
      //   (1') attacker presents OLD hash → but `refreshHash` is now NEW,
      //        so the lookup MISSES — the OLD hash is in
      //        `previousRefreshHashes` of the session row.
      //   Wait — `findByRefreshHash` only matches the current `refreshHash`
      //   column. So we never find the session row by an old hash.
      //
      // We need a SECOND lookup: did this presented hash match any
      // previousRefreshHashes row? If yes, the family is compromised.
      //
      // For an O(1) reuse check we'd index `previousRefreshHashes` with
      // a GIN index. V1 keeps it simple: scan the user's active sessions
      // and check each row's `previousRefreshHashes` array. With ≤ 100
      // active sessions per user this is fast enough.
      if (existing.previousRefreshHashes.includes(presentedHash.value)) {
        // Mass-revoke the family — the legitimate user already rotated
        // past this token, so a re-presentation is theft.
        await this.sessionRepo.revokeAllInFamily(
          tx,
          existing.familyId,
          'FAMILY_COMPROMISED',
        );
        throw new DomainError(
          'authentication.session.not_found',
          'Refresh token is not recognized',
        );
      }

      // First presentation of this hash (legitimate rotation).
      // V1.5 (audit H-1): the rotation write is now atomic — it
      // compares on the current hash and refuses to rotate if
      // another concurrent rotation has already moved the row.
      // Concurrent races are detected here as "reuse" because the
      // other rotation would have changed the refreshHash column,
      // causing our updateMany WHERE to match zero rows.
      const newPlaintext = this.refreshTokenGen.generate();
      const newHash = await RefreshTokenHash.fromPlaintext(newPlaintext);
      const now = this.clock.now();
      const newExpiresAt = new Date(
        now.getTime() + REFRESH_TOKEN_TTL_SECONDS * 1000,
      );
      const rotated = existing.rotateRefreshToken({
        newRefreshHash: newHash,
        clock: this.clock,
        newExpiresAt,
      });
      const swapped = await this.sessionRepo.rotateRefreshTokenAtomic(
        tx,
        presentedHash.value,
        {
          refreshHash: newHash.value,
          expiresAt: newExpiresAt,
          lastUsedAt: now,
          previousRefreshHashes: rotated.previousRefreshHashes,
        },
      );
      if (!swapped) {
        // Someone else rotated first — treat as reuse, mass-revoke.
        await this.sessionRepo.revokeAllInFamily(
          tx,
          existing.familyId,
          'FAMILY_COMPROMISED',
        );
        throw new DomainError(
          'authentication.session.not_found',
          'Refresh token is not recognized',
        );
      }
      const saved = Session.fromPersistence({
        ...rotated,
        mfaVerified: existing.mfaVerified,
        revokedAt: null,
        revokeReason: null,
      });

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
