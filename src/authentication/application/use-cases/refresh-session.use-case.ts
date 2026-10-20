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
import { RecordAuditEventUseCase } from '../../../engagement/application/use-cases/record-audit-event.use-case';

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
 * 2026-10-19 audit fix H-7: idempotent-retry grace window. A presented
 * hash found in `previousRefreshHashes` within this many milliseconds
 * of `lastRotatedAt` is a legitimate client retry (request timeout,
 * two tabs racing) — the same response is returned again WITHOUT a
 * second rotation. Outside the window, the same presentation is theft:
 * the session family is revoked as compromised.
 */
const ROTATION_GRACE_WINDOW_MS = 60 * 1000;

/**
 * What the transaction decided. Audit writes must happen AFTER the
 * transaction commits, so paths that need an audit trail return a
 * verdict instead of throwing and the use-case acts on it outside
 * the tx boundary.
 */
type RefreshOutcome =
  | { kind: 'tokens'; result: RefreshSessionResult }
  | { kind: 'grace_retry'; result: RefreshSessionResult }
  | {
      kind: 'compromise';
      userId: string;
      sessionId: string;
      familyId: string;
      revokedCount: number;
    }
  | { kind: 'mfa_required'; userId: string; sessionId: string };

/**
 * Refresh a session by rotating the refresh token.
 *
 * Lookup algorithm (2026-10-19 audit fix H-7 — reuse detection is no
 * longer dead code and legit double-refreshes no longer mass-revoke):
 *
 *   1. Hash the presented token and look up by CURRENT hash
 *      (`findByRefreshHash`).
 *      a. No row → SECOND lookup by rotation history
 *         (`findByPreviousHash`). Still no row → 401 "not_found": we
 *         have no evidence this token was ever valid.
 *      b. Row exists but revoked / expired → 401.
 *
 *   2. A row found via the rotation history means this token was
 *      already rotated out. Compare `lastRotatedAt` with now:
 *      a. Within the 60-second grace window → idempotent retry:
 *         return the session's current tokens WITHOUT rotating again.
 *         (The current plaintext is not stored, so the presented
 *         token — still valid inside the window — is returned.)
 *      b. Outside the grace window → FAMILY_COMPROMISED: revoke the
 *         whole family, audit `authentication.refresh.reuse_detected`
 *         + `authentication.refresh.family_revoked`, throw 401.
 *
 *   3. First presentation of the current hash (legitimate rotation).
 *      The rotation write is atomic (compare-and-swap on the current
 *      hash). If the CAS updates zero rows, a concurrent rotation won:
 *      re-read the row and run step 2's classification on it — the
 *      presented hash is now in its `previousRefreshHashes`. This
 *      removes the false-positive mass-revoke that previously fired
 *      for every concurrent double-refresh.
 *
 * 2026-10-19 audit fix C1: a session whose MFA verification is still
 * pending (`mfaVerified=false`) is refused here with 401
 * `authentication.mfa.required` — the REST path previously never
 * checked, which let a password-only attacker bypass MFA entirely.
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
    private readonly recordAuditEventUc: RecordAuditEventUseCase,
  ) {}

  public async execute(
    input: RefreshSessionInput,
  ): Promise<RefreshSessionResult> {
    const presentedHash = await RefreshTokenHash.fromPlaintext(
      input.refreshToken,
    );

    const outcome = await this.txRunner.run<RefreshOutcome>(
      async (tx: Tx): Promise<RefreshOutcome> => {
        const now = this.clock.now();
        const existing = await this.sessionRepo.findByRefreshHash(
          tx,
          presentedHash.value,
        );

        if (!existing) {
          // H-7: the promised second lookup. A presented hash that is
          // no longer the current hash but sits in a row's rotation
          // history is either a grace-window retry or a stolen token.
          const rotated = await this.sessionRepo.findByPreviousHash(
            tx,
            presentedHash.value,
          );
          if (!rotated) {
            throw new DomainError(
              'authentication.session.not_found',
              'Refresh token is not recognized',
            );
          }
          return this.classifyRotatedPresentation(
            tx,
            rotated,
            input.refreshToken,
            now,
          );
        }

        if (!existing.isAliveAt(now)) {
          throw new DomainError(
            'authentication.session.expired',
            'Refresh token is no longer valid',
          );
        }

        // Audit fix C1 (mirror of the OAuth grant check): refuse to
        // rotate a session whose MFA verification is still pending.
        if (!existing.mfaVerified) {
          return {
            kind: 'mfa_required',
            userId: existing.userId.value,
            sessionId: existing.id.value,
          };
        }

        // App-bound org-scope check. When the refresh carries an app's
        // defaultOrgSlug, the session must already be scoped to that
        // org. Without this, a user could refresh a session they
        // obtained via a different app — i.e. cross-app session leak.
        //
        // V1.5 fix: legacy sessions with `organizationId = NULL` are
        // accepted under any app context. V2 will require explicit
        // re-binding.
        if (input.appDefaultOrgSlug && existing.organizationId === null) {
          // Legacy unscoped session — accept (V1 backward-compat).
        } else if (
          input.appDefaultOrgSlug &&
          existing.organizationId !== null
        ) {
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

        // Legitimate rotation: mint a new refresh token, rotate the
        // stored hash atomically (compare-and-swap on the CURRENT
        // hash so two concurrent rotations can't both succeed).
        const newPlaintext = this.refreshTokenGen.generate();
        const newHash = await RefreshTokenHash.fromPlaintext(newPlaintext);
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
            lastRotatedAt: now,
            previousRefreshHashes: rotated.previousRefreshHashes,
          },
        );
        if (!swapped) {
          // CAS race loser — another rotation won. Re-read the row and
          // classify: our presented hash should now be in its rotation
          // history (legitimate concurrent retry), otherwise the
          // family is treated as compromised.
          const fresh = await this.sessionRepo.findById(tx, existing.id);
          if (
            fresh &&
            fresh.previousRefreshHashes.includes(presentedHash.value)
          ) {
            return this.classifyRotatedPresentation(
              tx,
              fresh,
              input.refreshToken,
              now,
            );
          }
          const revokedCount = await this.sessionRepo.revokeAllInFamily(
            tx,
            existing.familyId,
            'FAMILY_COMPROMISED',
          );
          return {
            kind: 'compromise',
            userId: existing.userId.value,
            sessionId: existing.id.value,
            familyId: existing.familyId,
            revokedCount,
          };
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
          kind: 'tokens',
          result: {
            refreshToken: newPlaintext,
            sessionId: saved.id.value,
            userId: saved.userId.value,
            familyId: saved.familyId,
            expiresAt: saved.expiresAt,
          },
        };
      },
    );

    // Post-commit actions: audits must be durable with the revocation.
    switch (outcome.kind) {
      case 'tokens':
      case 'grace_retry':
        return outcome.result;
      case 'mfa_required':
        await this.recordAuditEventUc.execute({
          userId: outcome.userId,
          eventType: 'authentication.mfa.required',
          payload: {
            sessionId: outcome.sessionId,
            outcome: 'refresh_rejected',
          },
        });
        throw new DomainError(
          'authentication.mfa.required',
          'Multi-factor authentication required; verify MFA on this session before refreshing',
          { sessionId: outcome.sessionId },
        );
      case 'compromise':
        await this.recordAuditEventUc.execute({
          userId: outcome.userId,
          eventType: 'authentication.refresh.reuse_detected',
          payload: {
            sessionId: outcome.sessionId,
            familyId: outcome.familyId,
          },
        });
        await this.recordAuditEventUc.execute({
          userId: outcome.userId,
          eventType: 'authentication.refresh.family_revoked',
          payload: {
            familyId: outcome.familyId,
            revokedCount: outcome.revokedCount,
            reason: 'FAMILY_COMPROMISED',
          },
        });
        // Generic 401 — don't tell the presenter we detected reuse.
        throw new DomainError(
          'authentication.session.not_found',
          'Refresh token is not recognized',
        );
    }
  }

  /**
   * Classify a presentation whose hash is in the session's rotation
   * history. Within the grace window → idempotent retry (no second
   * rotation, no revocation). Outside → family compromise.
   */
  private async classifyRotatedPresentation(
    tx: Tx,
    session: Session,
    presentedPlaintext: string,
    now: Date,
  ): Promise<RefreshOutcome> {
    if (!session.isAliveAt(now)) {
      throw new DomainError(
        'authentication.session.expired',
        'Refresh token is no longer valid',
      );
    }

    // C1 applies to retries too: an MFA-pending session gets no tokens
    // through any path.
    if (!session.mfaVerified) {
      return {
        kind: 'mfa_required',
        userId: session.userId.value,
        sessionId: session.id.value,
      };
    }

    const rotatedAt = session.lastRotatedAt;
    if (
      rotatedAt !== null &&
      now.getTime() - rotatedAt.getTime() <= ROTATION_GRACE_WINDOW_MS
    ) {
      // Idempotent retry. The current plaintext is not stored, so we
      // return the presented token — it remains valid until the grace
      // window closes. No state change: the rotation (and its
      // lastRotatedAt timestamp) from the first, winning request
      // stands.
      return {
        kind: 'grace_retry',
        result: {
          refreshToken: presentedPlaintext,
          sessionId: session.id.value,
          userId: session.userId.value,
          familyId: session.familyId,
          expiresAt: session.expiresAt,
        },
      };
    }

    const revokedCount = await this.sessionRepo.revokeAllInFamily(
      tx,
      session.familyId,
      'FAMILY_COMPROMISED',
    );
    return {
      kind: 'compromise',
      userId: session.userId.value,
      sessionId: session.id.value,
      familyId: session.familyId,
      revokedCount,
    };
  }
}
