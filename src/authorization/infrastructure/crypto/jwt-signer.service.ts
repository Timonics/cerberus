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
   *
   * Audit 2026-10-19: the cache stores the key's `expiresAt` alongside
   * the `CryptoKey` and re-checks it on every hit. Previously a cached
   * key was used forever — tokens kept verifying against an
   * expired-but-cached signing key until the process restarted or a
   * rotation happened to clear the cache.
   */
  private verifyingKeys: Map<
    string,
    { key: CryptoKey; expiresAt: Date | null }
  > = new Map();

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
    const now = new Date();
    let cached = this.verifyingKeys.get(kid);
    if (
      cached &&
      cached.expiresAt !== null &&
      cached.expiresAt.getTime() <= now.getTime()
    ) {
      // Expired keys are rejected, never used for verification —
      // drop the stale cache entry and fail closed.
      this.verifyingKeys.delete(kid);
      throw new Error(`Signing key kid=${kid} has expired`);
    }
    if (!cached) {
      cached = await this.loadKey(kid);
      this.verifyingKeys.set(kid, cached);
    }
    // V1.7 audit fix #14: explicitly pin the algorithm to RS256.
    // jose v5's `jwtVerify` accepts the algorithm from the token's
    // `alg` header by default — which works in V1 because every
    // signing key is RSA. But if a future PR ever changes the key
    // generator to support multiple algorithms (HS256, ES256),
    // this surface is a downgrade-attack vector: an attacker who
    // can mint any token can claim `alg: HS256` with the public
    // key as the HMAC secret. Locking to RS256 here makes that
    // attack impossible regardless of what the key generator
    // does in the future.
    const { payload } = await jwtVerify(params.token, cached.key, {
      issuer: params.issuer,
      audience: params.audience,
      algorithms: ['RS256'],
    });
    return payload;
  }

  /**
   * Load a key from the repo and import it as a `CryptoKey`, along with
   * its `expiresAt` so cache hits can re-check expiry. Throws if the
   * kid is unknown OR the key is past its `expiresAt`.
   */
  private async loadKey(kid: string): Promise<{
    key: CryptoKey;
    /** Null = the key never expires. */
    expiresAt: Date | null;
  }> {
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
    const cryptoKey: CryptoKey = await importPKCS8(key.privatePem, 'RS256');
    return { key: cryptoKey, expiresAt: key.expiresAt };
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
