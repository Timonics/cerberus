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
  /**
   * Whether the generated Prisma client knows the `lastRotatedAt`
   * column. Null = not yet probed; true/false cached after the first
   * write attempt. The column ships via migration
   * `20261019_b1_refresh_grace`; the generated client only learns it
   * after the schema owner adds it to schema.prisma and regenerates.
   * While false, writes degrade gracefully (no grace timestamp) rather
   * than failing the rotation.
   */
  private lastRotatedAtWritable: boolean | null = null;

  public constructor(private readonly prisma: PrismaService) {
    super();
  }

  /**
   * True when the error is Prisma rejecting `lastRotatedAt` as an
   * unknown argument — i.e. the generated client predates the column.
   * Any other validation error re-throws.
   */
  private static isMissingLastRotatedAtColumn(err: unknown): boolean {
    return (
      err instanceof Prisma.PrismaClientValidationError &&
      err.message.includes('lastRotatedAt')
    );
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

  public async findByPreviousHash(
    tx: Tx,
    refreshHash: string,
  ): Promise<Session | null> {
    const client = tx as PrismaTx;
    // GIN-free array membership: Prisma compiles `has` to
    // `previousRefreshHashes @> ARRAY[...]` (Postgres array contains).
    const row = await client.session.findFirst({
      where: {
        previousRefreshHashes: { has: refreshHash },
        revokedAt: null,
      },
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
    const update = {
      refreshHash: data.refreshHash,
      expiresAt: data.expiresAt,
      lastUsedAt: data.lastUsedAt,
      // 2026-10-19 audit fix H-7: persist the rotation timestamp so
      // the grace window survives restarts. Conditional on the
      // generated client knowing the column (see lastRotatedAtWritable).
      ...(session.lastRotatedAt !== null && this.lastRotatedAtWritable !== false
        ? { lastRotatedAt: session.lastRotatedAt }
        : {}),
      previousRefreshHashes: data.previousRefreshHashes,
      mfaVerified: data.mfaVerified,
      revokedAt: data.revokedAt,
      revokeReason: data.revokeReason,
    };
    try {
      const row = await client.session.upsert({
        where: { id: session.id.value },
        create: data,
        update,
      });
      if (session.lastRotatedAt !== null) {
        this.lastRotatedAtWritable = true;
      }
      return this.toDomain(row);
    } catch (err) {
      if (
        session.lastRotatedAt === null ||
        !PrismaSessionRepository.isMissingLastRotatedAtColumn(err)
      ) {
        throw err;
      }
      // The generated Prisma client predates the lastRotatedAt column
      // (the schema owner adds it to schema.prisma + regenerates; the
      // DB column comes from migration 20261019_b1_refresh_grace).
      // Degrade gracefully: the write succeeds without the grace
      // timestamp instead of failing the whole save.
      this.lastRotatedAtWritable = false;
      const row = await client.session.upsert({
        where: { id: session.id.value },
        create: data,
        update: {
          refreshHash: update.refreshHash,
          expiresAt: update.expiresAt,
          lastUsedAt: update.lastUsedAt,
          previousRefreshHashes: update.previousRefreshHashes,
          mfaVerified: update.mfaVerified,
          revokedAt: update.revokedAt,
          revokeReason: update.revokeReason,
        },
      });
      return this.toDomain(row);
    }
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
      lastRotatedAt: Date;
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
    // rows. The use-case then re-reads the row and classifies the
    // attempt (grace retry vs compromise) instead of mass-revoking.
    const where = {
      refreshHash: currentHash,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    };
    const baseData = {
      refreshHash: next.refreshHash,
      expiresAt: next.expiresAt,
      lastUsedAt: next.lastUsedAt,
      previousRefreshHashes: [...next.previousRefreshHashes],
    };

    if (this.lastRotatedAtWritable !== false) {
      try {
        const result = await client.session.updateMany({
          where,
          data: {
            ...baseData,
            // 2026-10-19 audit fix H-7: stamp the rotation so a
            // concurrent loser's retry can be classified against the
            // 60-second grace window.
            ...{ lastRotatedAt: next.lastRotatedAt },
          },
        });
        this.lastRotatedAtWritable = true;
        return result.count === 1;
      } catch (err) {
        if (!PrismaSessionRepository.isMissingLastRotatedAtColumn(err)) {
          throw err;
        }
        // The generated Prisma client predates the lastRotatedAt column
        // (the schema owner adds it to schema.prisma + regenerates; the
        // DB column comes from migration 20261019_b1_refresh_grace).
        // Degrade gracefully: rotation still works, the grace window is
        // simply unavailable (lastRotatedAt stays null) until the
        // client is regenerated.
        this.lastRotatedAtWritable = false;
      }
    }

    const result = await client.session.updateMany({
      where,
      data: baseData,
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
    /**
     * 2026-10-19 audit fix H-7: rotation timestamp for the grace
     * window. Optional — the column is added by migration
     * `20261019_b1_refresh_grace`; rows written before it (and the
     * generated client before the schema workstream regenerates)
     * simply don't carry it.
     */
    lastRotatedAt?: Date | null;
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
      lastRotatedAt: row.lastRotatedAt ?? null,
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
