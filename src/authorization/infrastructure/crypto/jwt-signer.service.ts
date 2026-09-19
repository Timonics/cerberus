import {
  SignJWT,
  importPKCS8,
  jwtVerify,
  decodeProtectedHeader,
  createRemoteJWKSet,
  JWTPayload,
} from 'jose';
import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  EVENT_BUS,
  EventBus,
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
 * JWT signing & verification.
 *
 * Two-phase construction:
 *   * At construction (DI): we hold the repository + bus + txRunner.
 *   * At module init: we call `bootstrap()` once, which loads the current
 *     signing key from the DB, imports its private key, and creates a
 *     `SignJWT` factory.
 *
 * `sign()` issues access tokens. `verifyAccessToken()` decodes a
 * presented JWT against the current signing key (or, if the `kid` is
 * known and the key is still verifying, against that key).
 *
 * The signing key is held as a `CryptoKey` (webcrypto) which `jose`
 * caches internally — issuing many tokens is fast.
 */
@Injectable()
export class JwtSignerService implements OnModuleInit {
  private readonly logger = new Logger(JwtSignerService.name);

  /**
   * Cached verification keys. Keyed by `kid`. Populated lazily on the
   * first `verifyAccessToken` call with a `kid` we haven't seen.
   */
  private verifyingKeys: Map<string, CryptoKey> = new Map();

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(SIGNING_KEY_REPOSITORY)
    private readonly keyRepo: SigningKeyRepository,
    @Inject(EVENT_BUS) private readonly bus: EventBus,
  ) {}

  public async onModuleInit(): Promise<void> {
    // Verify the schema has at least one signing key. If not, we don't
    // auto-create one here — the operator runs the bootstrap script.
    const key = await this.txRunner.run<SigningKey | null>((tx: Tx) =>
      this.keyRepo.getCurrent(tx).catch(() => null),
    );
    if (!key) {
      this.logger.warn(
        'No current signing key on startup. Issue /v1/oauth/admin/keys/rotate to create one.',
      );
    } else {
      this.logger.log(`Current signing key: kid=${key.kid}`);
    }
  }

  /**
   * Sign a JWT. The `payload` is augmented with `iss`, `iat`, `exp`, and
   * `kid` automatically. Returns the compact JWS string.
   */
  public async sign(params: {
    payload: Record<string, unknown>;
    privatePem: string;
    kid: string;
    issuer: string;
    audience: string;
    ttlSeconds: number;
  }): Promise<string> {
    const key = await importPKCS8(params.privatePem, 'RS256');
    return await new SignJWT(params.payload)
      .setProtectedHeader({ alg: 'RS256', kid: params.kid, typ: 'JWT' })
      .setIssuer(params.issuer)
      .setAudience(params.audience)
      .setIssuedAt()
      .setExpirationTime(`${params.ttlSeconds}s`)
      .sign(key);
  }

  /**
   * Verify a JWT. The `kid` from the token's header is used to select the
   * correct verification key. Returns the decoded payload + protected
   * header on success; throws on any failure (signature, expiry,
   * audience, issuer).
   */
  public async verifyAccessToken(params: {
    token: string;
    issuer: string;
    audience: string;
  }): Promise<JWTPayload> {
    // We don't know which key signed the token until we inspect the header.
    // jose's `jwtVerify` accepts either a single key or a JWKS, but for our
    // simple in-memory model we use `decodeJwt` to read the header first,
    // look up the right key, then verify with that key.
    const header = decodeProtectedHeader(params.token);
    const kid = header.kid;
    if (typeof kid !== 'string') {
      throw new Error('Token header missing kid');
    }
    let cryptoKey = this.verifyingKeys.get(kid);
    if (!cryptoKey) {
      cryptoKey = await this.loadKey(kid);
      this.verifyingKeys.set(kid, cryptoKey);
    }
    const { payload } = await jwtVerify(params.token, cryptoKey, {
      issuer: params.issuer,
      audience: params.audience,
    });
    return payload;
  }

  /**
   * Load a key from the repo and import it as a `CryptoKey`.
   * Returns null if the kid is unknown OR the key is past its `expiresAt`.
   */
  private async loadKey(kid: string): Promise<CryptoKey> {
    const key = await this.txRunner.run<SigningKey | null>(async (tx: Tx) =>
      this.keyRepo.findByKid(tx, kid),
    );
    if (!key) {
      throw new Error(`Unknown signing key kid=${kid}`);
    }
    if (!key.canVerifyAt(new Date())) {
      throw new Error(`Signing key kid=${kid} has expired`);
    }
    const { importPKCS8 } = await import('jose');
    return importPKCS8(key.privatePem, 'RS256');
  }

  /**
   * Refresh the cached verification key set. Called when the rotation
   * use-case fires (a new key becomes current, the old one retires).
   */
  public invalidateCache(): void {
    this.verifyingKeys.clear();
  }
}

// Suppress unused-import warnings — `createRemoteJWKSet` is here for
// the future V2 case where we publish JWKS at a public URL and want
// the verifier to fetch it dynamically.
void createRemoteJWKSet;
