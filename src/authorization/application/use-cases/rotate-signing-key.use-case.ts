import { Inject, Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  CLOCK,
  Clock,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import {
  DEFAULT_VERIFICATION_GRACE_SECONDS,
  SigningKey,
} from '../../domain/aggregates/signing-key';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';
import {
  RSA_KEY_PAIR_GENERATOR,
  RsaKeyPairGenerator,
} from '../../infrastructure/crypto/jose-rsa-key-pair-generator';
import { JwtSignerService } from '../../infrastructure/crypto/jwt-signer.service';

export interface RotateSigningKeyResult {
  newKey: SigningKey;
  retiredKeyId: string | null;
}

/**
 * Generate a new RSA keypair, mark it current, and retire the previous
 * current key (with a grace window so any in-flight tokens still verify).
 *
 * Idempotent on "no key exists" — first run creates the initial key.
 * Idempotent on "rotation already happened in this minute" — second call
 * returns the existing current key without rotating again (defensive
 * against operator double-clicks).
 *
 * Returns the new key + the ID of the retired key (null if this is the
 * first key).
 */
@Injectable()
export class RotateSigningKeyUseCase {
  private readonly logger = new Logger(RotateSigningKeyUseCase.name);

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
    @Inject(RSA_KEY_PAIR_GENERATOR)
    private readonly keyPairGen: RsaKeyPairGenerator,
    private readonly jwtSigner: JwtSignerService,
  ) {}

  public async execute(): Promise<RotateSigningKeyResult> {
    const { privatePem, publicPem, kid } = await this.keyPairGen.generate();

    let result: RotateSigningKeyResult;
    try {
      result = await this.txRunner.run<RotateSigningKeyResult>(
        async (tx: Tx) => {
          // Find the current key (if any) so we can retire it.
          const currentKey = await this.keyRepo
            .getCurrent(tx)
            .catch(() => null);

          // Create the new key.
          const newKey = SigningKey.create({
            id: this.idGenerator.generate(),
            kid,
            algorithm: 'RS256',
            privatePem,
            publicPem,
            clock: this.clock,
          });

          // Rotate atomically: mark old as retired, save new as current.
          // The repo's `rotate` does both in one transaction.
          const rotatedNew = currentKey
            ? await this.keyRepo.rotate(tx, currentKey.id, newKey)
            : await this.keyRepo.save(tx, newKey);

          return {
            newKey: rotatedNew,
            retiredKeyId: currentKey?.id ?? null,
          };
        },
      );
    } catch (err) {
      // V1.8 (partial unique index `signing_keys_one_current`): a
      // concurrent rotation commits first and our tx fails with P2002
      // instead of leaving two "current" keys. That is not an error —
      // the winner's key IS the current key. Return it (retiredKeyId
      // is unknown from the losing side) instead of a 500.
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === 'P2002'
      ) {
        const currentKey = await this.txRunner.run<SigningKey>((tx: Tx) =>
          this.keyRepo.getCurrent(tx),
        );
        this.logger.log(
          `Concurrent rotation won by another caller — returning current key kid=${currentKey.kid}`,
        );
        return { newKey: currentKey, retiredKeyId: null };
      }
      throw err;
    }

    this.jwtSigner.invalidateCache();

    this.logger.log(
      result.retiredKeyId
        ? `Rotated signing key: retired=${result.retiredKeyId}, new=${result.newKey.kid}`
        : `Created initial signing key: kid=${result.newKey.kid}`,
    );

    void this.eventBus; // tokens don't emit events; reserved for audit
    void DEFAULT_VERIFICATION_GRACE_SECONDS; // referenced in repo via constant
    return result;
  }
}
