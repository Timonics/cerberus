import { Injectable } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import { Session, isRevokeReason } from '../../domain/aggregates/session';
import { SessionRepository } from '../../domain/ports/session.repository.port';
import { IpAddress } from '../../domain/value-objects/ip-address';
import { RefreshTokenHash } from '../../domain/value-objects/refresh-token-hash';
import { SessionId } from '../../domain/value-objects/session-id';
import { UserAgent } from '../../domain/value-objects/user-agent';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `SessionRepository`.
 *
 * Notable: the repository exposes `revokeAllInFamily` and
 * `revokeAllForUser` as bulk operations. These run as a single
 * `UPDATE ... WHERE ...` to avoid an N+1 roundtrip on mass-revoke.
 */
@Injectable()
export class PrismaSessionRepository extends SessionRepository {
  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  public async findById(tx: Tx, id: SessionId): Promise<Session | null> {
    const client = tx as PrismaTx;
    const row = await client.session.findUnique({ where: { id: id.value } });
    return row ? this.toDomain(row) : null;
  }

  public async findByRefreshHash(
    tx: Tx,
    refreshHash: string,
  ): Promise<Session | null> {
    const client = tx as PrismaTx;
    const row = await client.session.findUnique({
      where: { refreshHash },
    });
    return row ? this.toDomain(row) : null;
  }

  public async findActiveByUserId(
    tx: Tx,
    userId: UserId,
  ): Promise<ReadonlyArray<Session>> {
    const client = tx as PrismaTx;
    const rows = await client.session.findMany({
      where: {
        userId: userId.value,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { issuedAt: 'desc' },
    });
    return rows.map((r) => this.toDomain(r));
  }

  public async save(tx: Tx, session: Session): Promise<Session> {
    const client = tx as PrismaTx;
    const data = {
      id: session.id.value,
      userId: session.userId.value,
      familyId: session.familyId,
      refreshHash: session.refreshHash.value,
      userAgent: session.userAgent?.value ?? null,
      ipAddress: session.ipAddress?.value ?? null,
      deviceLabel: session.deviceLabel,
      organizationId: session.organizationId?.value ?? null,
      issuedAt: session.issuedAt,
      expiresAt: session.expiresAt,
      lastUsedAt: session.lastUsedAt,
      previousRefreshHashes: [...session.previousRefreshHashes],
      mfaVerified: session.mfaVerified,
      revokedAt: session.revokedAt,
      revokeReason: session.revokeReason,
    };
    const row = await client.session.upsert({
      where: { id: session.id.value },
      create: data,
      update: {
        refreshHash: data.refreshHash,
        expiresAt: data.expiresAt,
        lastUsedAt: data.lastUsedAt,
        previousRefreshHashes: data.previousRefreshHashes,
        mfaVerified: data.mfaVerified,
        revokedAt: data.revokedAt,
        revokeReason: data.revokeReason,
      },
    });
    return this.toDomain(row);
  }

  public async markMfaVerified(
    tx: Tx,
    sessionId: SessionId,
  ): Promise<Session | null> {
    const client = tx as PrismaTx;
    const row = await client.session.update({
      where: { id: sessionId.value },
      data: { mfaVerified: true },
    });
    return this.toDomain(row);
  }

  public async rotateRefreshTokenAtomic(
    tx: Tx,
    currentHash: string,
    next: {
      refreshHash: string;
      expiresAt: Date;
      lastUsedAt: Date;
      previousRefreshHashes: ReadonlyArray<string>;
    },
  ): Promise<boolean> {
    const client = tx as PrismaTx;
    // Prisma's updateMany is the only safe way to do this atomically:
    // it issues a single UPDATE ... WHERE refreshHash = $current,
    // and the database applies it in one statement. Under READ
    // COMMITTED, two concurrent rotations can both pass an earlier
    // findByRefreshHash() check, but only one updateMany succeeds —
    // the second's WHERE clause sees the new hash and updates zero
    // rows. count === 0 ⇒ reuse detected.
    const result = await client.session.updateMany({
      where: {
        refreshHash: currentHash,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: {
        refreshHash: next.refreshHash,
        expiresAt: next.expiresAt,
        lastUsedAt: next.lastUsedAt,
        previousRefreshHashes: [...next.previousRefreshHashes],
      },
    });
    return result.count === 1;
  }

  public async delete(tx: Tx, id: SessionId): Promise<void> {
    const client = tx as PrismaTx;
    await client.session.delete({ where: { id: id.value } });
  }

  public async revokeAllInFamily(
    tx: Tx,
    familyId: string,
    reason: 'PASSWORD_CHANGED' | 'FAMILY_COMPROMISED' | 'ADMIN_REVOKED',
  ): Promise<number> {
    const client = tx as PrismaTx;
    const result = await client.session.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: new Date(), revokeReason: reason },
    });
    return result.count;
  }

  public async revokeAllForUser(
    tx: Tx,
    userId: UserId,
    reason: 'PASSWORD_CHANGED' | 'ADMIN_REVOKED',
  ): Promise<number> {
    const client = tx as PrismaTx;
    const result = await client.session.updateMany({
      where: { userId: userId.value, revokedAt: null },
      data: { revokedAt: new Date(), revokeReason: reason },
    });
    return result.count;
  }

  private toDomain(row: {
    id: string;
    userId: string;
    familyId: string;
    refreshHash: string;
    userAgent: string | null;
    ipAddress: string | null;
    deviceLabel: string | null;
    organizationId: string | null;
    issuedAt: Date;
    expiresAt: Date;
    lastUsedAt: Date | null;
    /** V1.5: chain of rotated refresh-token hashes (reuse detection). */
    previousRefreshHashes?: string[];
    /** V1.5 (audit C-4): MFA-verified flag. Defaults to true so legacy
     *  sessions (pre-V1.5 schema) are still treated as verified. */
    mfaVerified?: boolean;
    revokedAt: Date | null;
    revokeReason: string | null;
  }): Session {
    return Session.fromPersistence({
      id: SessionId.rehydrate(row.id),
      userId: UserId.rehydrate(row.userId),
      familyId: row.familyId,
      refreshHash: RefreshTokenHash.rehydrate(row.refreshHash),
      userAgent: row.userAgent ? UserAgent.rehydrate(row.userAgent) : null,
      ipAddress: row.ipAddress ? IpAddress.rehydrate(row.ipAddress) : null,
      deviceLabel: row.deviceLabel,
      organizationId: row.organizationId
        ? OrgId.rehydrate(row.organizationId)
        : null,
      issuedAt: row.issuedAt,
      expiresAt: row.expiresAt,
      lastUsedAt: row.lastUsedAt,
      previousRefreshHashes: row.previousRefreshHashes ?? [],
      mfaVerified: row.mfaVerified ?? true,
      revokedAt: row.revokedAt,
      revokeReason:
        row.revokeReason && isRevokeReason(row.revokeReason)
          ? row.revokeReason
          : null,
    });
  }
}
