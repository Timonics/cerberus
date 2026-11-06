/**
 * e2e global setup — ensures a current signing key exists before any
 * suite boots.
 *
 * Token issuance (login, refresh, OAuth grants) requires an RS256
 * signing key row. Production gets one from the operator rotating keys
 * via `POST /v1/oauth/admin/keys/rotate`; the long-lived dev database
 * accumulated keys the same way, which is why suites passed locally.
 * CI starts from a fresh database on every run, so without this seed
 * every login returns 500 ("No current signing key") and every
 * login-dependent suite fails.
 *
 * Runs once per `npm run test:e2e` invocation, in the main jest
 * process, before any worker boots a Nest application. Mirrors
 * `JoseRsaKeyPairGenerator` (RS256, 2048-bit, PKCS#8/SPKI PEMs) so
 * the row is indistinguishable from a rotated one. Idempotent: a
 * database that already has a current key is left untouched.
 */

import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { PrismaClient } from '@prisma/client';

export default async function globalSetup(): Promise<void> {
  // Suites share one Redis (and thus one per-IP rate-limit bucket).
  // The default 60 req/min/IP is tripped when two parallel suites
  // burst registrations mid-run; the per-app reset at boot doesn't
  // cover that window. Raise the per-IP budget for the e2e run only —
  // this runs in the main jest process before workers spawn, so the
  // values are inherited by every suite. Suites that pin their own
  // limits (per-email-rate-limit sets RATE_LIMIT_PER_EMAIL_MAX) are
  // unaffected — this touches only the per-IP bucket.
  process.env.RATE_LIMIT_MAX = process.env.RATE_LIMIT_MAX ?? '10000';

  const url =
    process.env.DATABASE_URL ??
    'postgresql://cerberus:cerberus@localhost:5434/cerberus';
  const prisma = new PrismaClient({
    datasources: { db: { url } },
  });
  try {
    const current = await prisma.signingKey.findFirst({
      where: { isCurrent: true },
    });
    if (current) {
      return;
    }
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
    await prisma.signingKey.create({
      data: { kid, algorithm: 'RS256', privatePem, publicPem, isCurrent: true },
    });
    console.log(`[e2e setup] seeded signing key ${kid}`);
  } finally {
    await prisma.$disconnect();
  }
}
