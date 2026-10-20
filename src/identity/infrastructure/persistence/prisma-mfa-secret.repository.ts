import { Prisma, PrismaClient } from '@prisma/client';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Tx } from '../../../shared/domain/persistence/tx';
import { MfaSecret, RecoveryCode } from '../../domain/aggregates/mfa-secret';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import { TotpSecretCipher } from '../security/totp-secret-cipher';

type PrismaTx = Prisma.TransactionClient | PrismaClient;

/**
 * Prisma adapter for `MfaSecretRepository`.
 *
 * Manages both the `mfa_secrets` and `recovery_codes` tables. On
 * `findById`, both are loaded together. On `save`, the secret row is
 * upserted and the recovery codes are deleted-and-reinserted (we
 * can't incrementally diff them; the aggregate owns the set).
 *
 * On `delete`, both rows are removed via the FK cascade.
 *
 * 2026-10-19 audit fix H-5a: the TOTP secret column is encrypted with
 * AES-256-GCM (`TotpSecretCipher`) before it is written and decrypted
 * on load. Recovery-code hashes are argon2 and stay as-is. Legacy
 * plaintext rows decrypt as pass-through and are re-encrypted on the
 * next save.
 */
@Injectable()
export class PrismaMfaSecretRepository extends MfaSecretRepository {
  public constructor(
    private readonly prisma: PrismaService,
    private readonly cipher: TotpSecretCipher,
  ) {
    super();
  }

  public async findById(tx: Tx, userId: UserId): Promise<MfaSecret | null> {
    const client = tx as PrismaTx;
    const row = await client.mfaSecret.findUnique({
      where: { userId: userId.value },
      include: { recoveryCodes: true },
    });
    return row ? this.toDomain(row) : null;
  }

  public async save(tx: Tx, secret: MfaSecret): Promise<MfaSecret> {
    const client = tx as PrismaTx;
    const encryptedSecret = this.cipher.encrypt(secret.secret);

    // Step 1: upsert the secret row.
    await client.mfaSecret.upsert({
      where: { userId: secret.userId.value },
      create: {
        id: secret.id,
        userId: secret.userId.value,
        secret: encryptedSecret,
        confirmed: secret.confirmed,
      },
      update: {
        secret: encryptedSecret,
        confirmed: secret.confirmed,
      },
    });

    // Step 2: replace the recovery-code set.
    await client.recoveryCode.deleteMany({
      where: { mfaSecret: { userId: secret.userId.value } },
    });
    if (secret.recoveryCodes.length > 0) {
      await client.recoveryCode.createMany({
        data: secret.recoveryCodes.map((c) => ({
          id: c.id,
          mfaSecretId: secret.id,
          codeHash: c.codeHash,
          usedAt: c.usedAt,
        })),
      });
    }

    return secret;
  }

  public async delete(tx: Tx, userId: UserId): Promise<void> {
    const client = tx as PrismaTx;
    await client.mfaSecret.delete({ where: { userId: userId.value } });
  }

  private toDomain(row: {
    id: string;
    userId: string;
    secret: string;
    confirmed: boolean;
    createdAt: Date;
    updatedAt: Date;
    recoveryCodes: Array<{
      id: string;
      mfaSecretId: string;
      codeHash: string;
      usedAt: Date | null;
    }>;
  }): MfaSecret {
    return MfaSecret.fromPersistence({
      id: row.id,
      userId: UserId.rehydrate(row.userId),
      secret: this.cipher.decrypt(row.secret),
      confirmed: row.confirmed,
      recoveryCodes: row.recoveryCodes.map((rc) =>
        RecoveryCode.fromPersistence({
          id: rc.id,
          mfaSecretId: rc.mfaSecretId,
          codeHash: rc.codeHash,
          usedAt: rc.usedAt,
        }),
      ),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }
}

export const PRISMA_MFA_SECRET_REPOSITORY = MFA_SECRET_REPOSITORY;
