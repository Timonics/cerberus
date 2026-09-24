/**
 * H-1 — Refresh token atomic-rotation contract test.
 *
 * Pins the Prisma persistence contract: that the
 * `SessionRepository.rotateRefreshTokenAtomic()` UPDATE-with-WHERE
 * really is atomic, that a concurrent rotation cannot mint two
 * valid refresh tokens for the same session.
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

  it('exactly one of two concurrent rotations succeeds', async () => {
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

    // The critical invariant: at most one rotation succeeds.
    // Two-fulfill would mean the race minted two valid refresh
    // tokens for the same session — the exact H-1 bug.
    expect(fulfilled.length).toBeLessThanOrEqual(1);
    expect(fulfilled.length + rejected.length).toBe(2);

    if (rejected.length > 0) {
      const reason = rejected[0].reason as {
        code?: string;
      };
      // Use-case maps reuse to authentication.session.not_found
      // for ambiguity (so attackers can't probe).
      expect(reason.code).toBe('authentication.session.not_found');
    }
  }, 30000);
});
