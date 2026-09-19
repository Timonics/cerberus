import { Inject, Injectable } from '@nestjs/common';
import { exportJWK, importSPKI } from 'jose';
import {
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { SigningKey } from '../../domain/aggregates/signing-key';
import {
  SIGNING_KEY_REPOSITORY,
  SigningKeyRepository,
} from '../../domain/ports/signing-key.repository.port';

/**
 * Build a JWKS document (RFC 7517 §5) from all currently-verifying
 * signing keys.
 *
 * The output shape:
 * ```
 * {
 *   "keys": [
 *     { "kty": "RSA", "kid": "...", "alg": "RS256", "use": "sig", "n": "...", "e": "..." },
 *     ...
 *   ]
 * }
 * ```
 *
 * Published at `GET /.well-known/jwks.json`. Resource servers fetch
 * this to verify JWTs issued by the auth service.
 */
@Injectable()
export class GetJwksUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
  ) {}

  public async execute(now: Date): Promise<{ keys: ReadonlyArray<unknown> }> {
    const keys = await this.txRunner.run<ReadonlyArray<SigningKey>>(
      async (tx: Tx) => this.keyRepo.findVerifyingAt(tx, now),
    );

    const jwksKeys = await Promise.all(
      keys.map(async (key) => {
        // Build the JWK from the PUBLIC key only. We never load the
        // private key for JWKS publication — that would leak `d`, `p`,
        // `q`, etc. into the response. (jose's `exportJWK` on a private
        // CryptoKey DOES include private params by default, which is
        // why we explicitly import via `importSPKI` here.)
        const publicCryptoKey = await importSPKI(key.publicPem, 'RS256');
        const jwk = (await exportJWK(publicCryptoKey)) as unknown as Record<
          string,
          unknown
        >;
        return {
          kty: jwk.kty,
          n: jwk.n,
          e: jwk.e,
          alg: key.algorithm,
          kid: key.kid,
          use: 'sig',
        };
      }),
    );

    return { keys: jwksKeys };
  }
}
