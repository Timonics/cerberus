import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { Injectable } from '@nestjs/common';

/**
 * Port for RSA keypair generation.
 *
 * The default uses `jose.generateKeyPair` with RS256 (2048-bit RSA,
 * SHA-256) — the recommended default for OAuth2 / OIDC deployments.
 */
export interface RsaKeyPairGenerator {
  generate(): Promise<{ privatePem: string; publicPem: string; kid: string }>;
}

export const RSA_KEY_PAIR_GENERATOR = Symbol('RsaKeyPairGenerator');

/**
 * Default RSA keypair generator.
 *
 * Uses `jose.generateKeyPair('RS256')` with `extractable: true` so we
 * can export the private key as PEM for persistence. The `kid` is a
 * random 8-byte hex string — short enough to keep JWKS documents small,
 * long enough that collisions are vanishingly unlikely.
 */
@Injectable()
export class JoseRsaKeyPairGenerator implements RsaKeyPairGenerator {
  public async generate(): Promise<{
    privatePem: string;
    publicPem: string;
    kid: string;
  }> {
    const { privateKey, publicKey } = await generateKeyPair('RS256', {
      extractable: true,
      modulusLength: 2048,
    });
    const [privatePem, publicPem] = await Promise.all([
      exportPKCS8(privateKey),
      exportSPKI(publicKey),
    ]);
    const kidBytes = new Uint8Array(8);
    crypto.getRandomValues(kidBytes);
    const kid = Array.from(kidBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return { privatePem, publicPem, kid };
  }
}
