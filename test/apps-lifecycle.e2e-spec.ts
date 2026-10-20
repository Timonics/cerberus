/**
 * Apps module — register + rotate + revoke + verify flow.
 *
 * These use-cases previously had no integration test. Now we pin
 * the full lifecycle end-to-end against real Postgres:
 *   - RegisterAppUseCase mints an initial key
 *   - VerifyAppApiKeyUseCase accepts the plaintext
 *   - RotateAppApiKeyUseCase issues a new key + auto-revokes the
 *     old one (V1.5 fix)
 *   - RevokeAppUseCase revokes the app entirely
 *   - VerifyAppApiKeyUseCase rejects the revoked key
 */

import { randomUUID } from 'node:crypto';
import { RegisterAppUseCase } from '../src/apps/application/use-cases/register-app.use-case';
import { RotateAppApiKeyUseCase } from '../src/apps/application/use-cases/rotate-app-api-key.use-case';
import { RevokeAppUseCase } from '../src/apps/application/use-cases/revoke-app.use-case';
import { VerifyAppApiKeyUseCase } from '../src/apps/application/use-cases/verify-app-api-key.use-case';
import { buildIntegrationContext, teardown } from './harness';

describe('Apps module lifecycle (integration)', () => {
  let ctx: Awaited<ReturnType<typeof buildIntegrationContext>>;
  let registerUc: RegisterAppUseCase;
  let rotateUc: RotateAppApiKeyUseCase;
  let revokeUc: RevokeAppUseCase;
  let verifyUc: VerifyAppApiKeyUseCase;

  beforeAll(async () => {
    ctx = await buildIntegrationContext();
    registerUc = ctx.get(RegisterAppUseCase);
    rotateUc = ctx.get(RotateAppApiKeyUseCase);
    revokeUc = ctx.get(RevokeAppUseCase);
    verifyUc = ctx.get(VerifyAppApiKeyUseCase);
  });

  afterAll(async () => {
    await ctx.close();
    await teardown();
  });

  it('full lifecycle: register → verify → rotate → verify → revoke → reject', async () => {
    // 1. Register
    const reg = await registerUc.execute({
      name: `lifecycle-${randomUUID()}`,
      description: 'Test app',
      defaultOrgSlug: null,
      contactEmail: 'lifecycle@cerberus.local',
      ttlSeconds: 3600,
    });
    expect(reg.app.id).toBeTruthy();
    expect(reg.plaintextApiKey).toBeTruthy();
    expect(reg.app.revokedAt).toBeNull();

    // 2. Verify the plaintext key works.
    const verify1 = await verifyUc.execute({
      appId: reg.app.id,
      plaintextApiKey: reg.plaintextApiKey,
    });
    expect(verify1).not.toBeNull();
    expect(verify1!.appId).toBe(reg.app.id);
    expect(verify1!.role).toBe('APP');

    // 3. Rotate → new key issued, old one invalidated.
    const rotated = await rotateUc.execute(reg.app.id, 3600);
    expect(rotated.plaintextApiKey).not.toBe(reg.plaintextApiKey);
    expect(rotated.app.id).toBe(reg.app.id);

    // Old key should now throw. VerifyAppApiKeyUseCase collapses every
    // credential failure (unknown app / revoked app / wrong secret /
    // stale key) into the ONE uniform code so the endpoint can't be
    // used as a key-state oracle.
    await expect(
      verifyUc.execute({
        appId: reg.app.id,
        plaintextApiKey: reg.plaintextApiKey,
      }),
    ).rejects.toMatchObject({ code: 'app.credentials.invalid' });

    // New key works.
    const verify2 = await verifyUc.execute({
      appId: reg.app.id,
      plaintextApiKey: rotated.plaintextApiKey,
    });
    expect(verify2).not.toBeNull();
    expect(verify2!.appId).toBe(reg.app.id);

    // 4. Revoke the app entirely.
    await revokeUc.execute(reg.app.id);

    // The new key should now also be rejected. VerifyAppApiKeyUseCase
    // deliberately returns the SAME uniform code for a revoked app —
    // a distinct 'app.revoked' here would let callers probe app
    // lifecycle state.
    await expect(
      verifyUc.execute({
        appId: reg.app.id,
        plaintextApiKey: rotated.plaintextApiKey,
      }),
    ).rejects.toMatchObject({ code: 'app.credentials.invalid' });
  });

  it('rotate on a revoked app throws', async () => {
    const reg = await registerUc.execute({
      name: `revoked-rotate-${randomUUID()}`,
      description: null,
      defaultOrgSlug: null,
      contactEmail: 'revoked-rotate@cerberus.local',
      ttlSeconds: 3600,
    });
    await revokeUc.execute(reg.app.id);

    await expect(rotateUc.execute(reg.app.id, 3600)).rejects.toMatchObject({
      code: 'app.revoked',
    });
  });
});
