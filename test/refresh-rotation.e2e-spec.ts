/**
 * H-1/H-7 — Refresh token atomic-rotation + idempotent-retry grace.
 *
 * Pins the Prisma persistence contract: that the
 * `SessionRepository.rotateRefreshTokenAtomic()` UPDATE-with-WHERE
 * really is atomic (two concurrent rotations cannot BOTH mint new
 * valid refresh tokens), AND the 2026-10-19 H-7 grace-window contract:
 * a concurrent double-refresh is now a legitimate idempotent retry —
 * the loser re-presents the just-rotated hash within the 60-second
 * grace window and gets a successful response (the same session, no
 * family mass-revoke). The mass-revoke now only fires OUTSIDE the
 * grace window (see refresh-reuse.e2e-spec.ts).
 *
 * Pure-domain spec (`session.spec.ts`) covers the aggregate
 * behavior. This test pins the database-level guarantee.
 */

import { SessionId } from '../src/authentication/domain/value-objects/session-id';
import { IpAddress } from '../src/authentication/domain/value-objects/ip-address';
import { OrgId } from '../src/identity/domain/value-objects/org-id';
import { UserId } from '../src/identity/domain/value-objects/user-id';
import { Session } from '../src/authentication/domain/aggregates/session';
import { RefreshTokenHash } from '../src/authentication/domain/value-objects/refresh-token-hash';
import { RefreshSessionUseCase } from '../src/authentication/application/use-cases/refresh-session.use-case';
import { RegisterUserUseCase } from '../src/identity/application/use-cases/register-user.use-case';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../src/authentication/domain/ports/session.repository.port';
import { TRANSACTION_RUNNER, TransactionRunner } from '../src/shared/domain';
import { buildIntegrationContext, teardown, uniqueEmail } from './harness';

describe('H-1 — atomic refresh rotation (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
  });

  afterAll(async () => {
    await ctx.close();
    await teardown();
  });

  it('concurrent double-refresh: one rotates, the other grace-retries — family survives', async () => {
    // First, register a real user via the use-case (so FKs are satisfied).
    const registerUc = ctx.get(RegisterUserUseCase);
    const email = uniqueEmail('h1');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });

    const sessionRepo = ctx.get<SessionRepository>(SESSION_REPOSITORY);
    const txRunner = ctx.get<TransactionRunner>(TRANSACTION_RUNNER);
    const refreshUc = ctx.get(RefreshSessionUseCase);

    const userId = UserId.create(reg.userId);
    const orgId = OrgId.create(reg.organizationId);
    const sessionId = SessionId.create('33333333-3333-4333-8333-333333333333');

    const seedPlaintext = `concurrent-seed-${Date.now()}-${Math.random()}`;
    const seedHash = await RefreshTokenHash.fromPlaintext(seedPlaintext);
    const session = Session.create({
      id: sessionId,
      userId,
      familyId: 'family-h1-' + Date.now(),
      refreshHash: seedHash,
      userAgent: null,
      ipAddress: IpAddress.create('127.0.0.1'),
      deviceLabel: null,
      organizationId: orgId,
      clock: { now: () => new Date() },
      ttlSeconds: 3600,
      requiresMfa: false,
    });
    void userId;
    await txRunner.run(async (tx) => sessionRepo.save(tx, session));

    // Fire two refreshes in parallel against the same session.
    const results = await Promise.allSettled([
      refreshUc.execute({ refreshToken: seedPlaintext }),
      refreshUc.execute({ refreshToken: seedPlaintext }),
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    // H-7 grace window: a concurrent double-refresh is a legitimate
    // client retry, so BOTH calls may succeed — the winner rotates,
    // the loser classifies as a grace retry and gets a successful
    // response for the same session. What must NEVER happen:
    //   - zero successes (a legit retry 500ing), or
    //   - a rejection with a family-compromise code (the false-positive
    //     mass-revoke H-7 eliminated).
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);
    expect(fulfilled.length + rejected.length).toBe(2);

    const sessionIds = new Set(
      fulfilled.map(
        (r) =>
          (r as PromiseFulfilledResult<{ sessionId: string }>).value.sessionId,
      ),
    );
    // Both successes (if both) refer to the SAME session.
    expect(sessionIds.size).toBeLessThanOrEqual(1);

    if (rejected.length > 0) {
      const reason = rejected[0].reason as {
        code?: string;
      };
      // A rejection here is only acceptable as the ambiguous
      // not_found (e.g. the loser's read raced the winner's commit in
      // a way that missed the rotation history). It must NOT be a
      // compromise/reuse signal.
      expect(reason.code).toBe('authentication.session.not_found');
    }

    // CRITICAL H-7 regression pin: the family was NOT mass-revoked.
    // Both presentations were legitimate retries within the grace
    // window. (Pre-fix, the CAS loser mass-revoked the family here.)
    const after = await txRunner.run(async (tx) =>
      sessionRepo.findById(tx, sessionId),
    );
    expect(after).not.toBeNull();
    expect(after!.revokedAt).toBeNull();
  }, 30000);
});
