import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

/**
 * AES-256-GCM helpers for encrypting small secret values at rest.
 *
 * V1.8 audit fix C3: engagement "requested" events carry the
 * plaintext email-verification / password-reset token so the mail
 * sender can render the link. The outbox row sits in the same
 * database as the (hashed) engagement tables, so persisting the
 * token there in plaintext would let any DB backup / replica reader
 * / SQLi replay the live link. Instead the token field is written
 * as an AES-256-GCM ciphertext with a key derived from
 * `TOKEN_SECRET` (scrypt, 32 bytes).
 *
 * Wire format: `v1:<iv>:<authTag>:<ciphertext>` — all three binary
 * parts base64-encoded. The version prefix lets readers distinguish
 * ciphertexts from legacy plaintext rows (see `isAeadCiphertext`),
 * which are passed through until they age out of the outbox TTL.
 *
 * This module is intentionally free of NestJS imports: it is used
 * from both the outbox writer (PrismaOutbox) and the pure-function
 * rehydrate step, so it lives below the DI graph.
 */

const VERSION_PREFIX = 'v1';

/** Fixed salt — the key only rotates when TOKEN_SECRET rotates. */
const KEY_DERIVATION_SALT = 'cerberus-outbox-aead-v1';

/**
 * Dev fallback for `TOKEN_SECRET`. MUST mirror the `tokenSecret`
 * default in `src/config/configuration.ts` — this module reads the
 * environment directly because it is used outside the DI graph.
 */
const DEV_TOKEN_SECRET_FALLBACK =
  'dev-only-insecure-default-please-override-32chars';

/** Derive a 32-byte AES-256 key from the server secret. */
export function deriveAeadKey(secret: string): Buffer {
  return scryptSync(secret, KEY_DERIVATION_SALT, 32);
}

/** Lazily-cached process-wide key (same lifecycle as the JWT secret). */
let cachedKey: Buffer | null = null;

export function getOutboxAeadKey(): Buffer {
  if (!cachedKey) {
    cachedKey = deriveAeadKey(
      process.env['TOKEN_SECRET'] ?? DEV_TOKEN_SECRET_FALLBACK,
    );
  }
  return cachedKey;
}

export function encryptAead(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [
    VERSION_PREFIX,
    iv.toString('base64'),
    tag.toString('base64'),
    ciphertext.toString('base64'),
  ].join(':');
}

/**
 * True when `value` is a ciphertext produced by `encryptAead`.
 * Anything else (legacy plaintext rows, empty/missing values) is
 * NOT a ciphertext.
 */
export function isAeadCiphertext(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(`${VERSION_PREFIX}:`);
}

export function decryptAead(blob: string, key: Buffer): string {
  const parts = blob.split(':');
  if (parts.length !== 4 || parts[0] !== VERSION_PREFIX) {
    throw new Error('aead: unsupported ciphertext format');
  }
  const [, ivB64, tagB64, ctB64] = parts;
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivB64, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}
