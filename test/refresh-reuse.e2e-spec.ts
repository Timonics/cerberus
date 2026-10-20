/**
 * H-7 — Refresh-token reuse BEYOND the grace window.
 *
 * Pins the compromise path of the 2026-10-19 reuse-detection rework:
 *   1. A session rotates (legitimate refresh) — the old hash moves
 *      into `previousRefreshHashes` and `lastRotatedAt` is stamped.
 *   2. Presenting the old token WITHIN the 60s grace window is an
 *      idempotent retry (covered by refresh-rotation.e2e-spec.ts).
 *   3. Presenting the old token AFTER the grace window is theft:
 *      the whole session family is revoked as FAMILY_COMPROMISED and
 *      BOTH audit rows are written —
 *        authentication.refresh.reuse_detected
 *        authentication.refresh.family_revoked
 *      — and the presenter gets only the ambiguous 401
 *      `authentication.session.not_found` (never a signal that reuse
 *      was detected).
 *
 * The grace window is wall-clock based on `lastRotatedAt`, so the
 * test backdates that column directly (no 60s test sleep).
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
import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'node:crypto';
import { buildIntegrationContext, teardown, uniqueEmail } from './harness';

describe('H-7 — refresh reuse beyond grace (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let prisma: PrismaClient;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    prisma = new PrismaClient();
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await ctx.close();
    await teardown();
  });

  it('old token past the grace window → family revoked + reuse/family_revoked audit rows', async () => {
    const registerUc = ctx.get(RegisterUserUseCase);
    const sessionRepo = ctx.get<SessionRepository>(SESSION_REPOSITORY);
    const txRunner = ctx.get<TransactionRunner>(TRANSACTION_RUNNER);
    const refreshUc = ctx.get(RefreshSessionUseCase);

    const email = uniqueEmail('h7-reuse');
    const password = 'correct horse battery staple 1!';
    const reg = await registerUc.execute({
      email,
      password,
      organizationSlug: null,
      appDefaultOrgSlug: null,
    });

    // Seed a family of TWO sessions (proves the revoke is family-wide,
    // not just the presented session's row).
    const familyId = `family-h7-${Date.now()}`;
    const userId = UserId.create(reg.userId);
    const orgId = OrgId.create(reg.organizationId);
    const mkSession = async (id: string, plaintext: string) => {
      const hash = await RefreshTokenHash.fromPlaintext(plaintext);
      const session = Session.create({
        id: SessionId.create(id),
        userId,
        familyId,
        refreshHash: hash,
        userAgent: null,
        ipAddress: IpAddress.create('127.0.0.1'),
        deviceLabel: null,
        organizationId: orgId,
        clock: { now: () => new Date() },
        ttlSeconds: 3600,
        requiresMfa: false,
      });
      await txRunner.run(async (tx) => sessionRepo.save(tx, session));
    };
    // Unique session ids per run — the session repo upserts on id but
    // its UPDATE clause never rewrites userId/familyId, so hardcoded
    // ids would keep the FIRST run's user/family on the row and the
    // audit assertions below would filter on values the use-case never
    // saw.
    const victimId = randomUUID();
    const siblingId = randomUUID();
    const victimPlaintext = `h7-victim-${Date.now()}-${Math.random()}`;
    const siblingPlaintext = `h7-sibling-${Date.now()}-${Math.random()}`;
    await mkSession(victimId, victimPlaintext);
    await mkSession(siblingId, siblingPlaintext);

    // 1. Legitimate rotation of the victim session.
    const rotated = await refreshUc.execute({ refreshToken: victimPlaintext });
    expect(rotated.sessionId).toBe(victimId);
    expect(rotated.refreshToken).not.toBe(victimPlaintext);

    // 2. Backdate lastRotatedAt to 2 minutes ago — outside the 60s
    //    grace window.
    await prisma.session.update({
      where: { id: victimId },
      data: { lastRotatedAt: new Date(Date.now() - 120_000) },
    });

    // 3. The attacker presents the rotated-out old token.
    await expect(
      refreshUc.execute({ refreshToken: victimPlaintext }),
    ).rejects.toMatchObject({
      // Ambiguous on purpose: the presenter must not learn that reuse
      // was detected.
      code: 'authentication.session.not_found',
    });

    // 4. The ENTIRE family is revoked as compromised — including the
    //    sibling session whose token was never presented.
    const victimAfter = await prisma.session.findUnique({
      where: { id: victimId },
    });
    const siblingAfter = await prisma.session.findUnique({
      where: { id: siblingId },
    });
    expect(victimAfter?.revokedAt).not.toBeNull();
    expect(victimAfter?.revokeReason).toBe('FAMILY_COMPROMISED');
    expect(siblingAfter?.revokedAt).not.toBeNull();
    expect(siblingAfter?.revokeReason).toBe('FAMILY_COMPROMISED');

    // 5. Both audit rows exist (reuse detection is now visible — the
    //    pre-fix code revoked silently).
    // 5. Both audit rows exist (reuse detection is now visible — the
    //    pre-fix code revoked silently).
    const reuseAudit = await prisma.auditLog.findFirst({
      where: {
        userId: reg.userId,
        eventType: 'authentication.refresh.reuse_detected',
        payload: { path: ['familyId'], equals: familyId },
      },
    });
    expect(reuseAudit).not.toBeNull();
    const familyAudit = await prisma.auditLog.findFirst({
      where: {
        userId: reg.userId,
        eventType: 'authentication.refresh.family_revoked',
        payload: { path: ['familyId'], equals: familyId },
      },
    });
    expect(familyAudit).not.toBeNull();
    expect(
      (familyAudit!.payload as { revokedCount: number }).revokedCount,
    ).toBeGreaterThanOrEqual(2);
  }, 30000);
});
