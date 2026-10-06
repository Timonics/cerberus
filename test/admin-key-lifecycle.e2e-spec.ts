/**
 * Admin API key issue + revoke lifecycle.
 *
 * The admin API key is a high-privilege credential (it bypasses
 * the IP allowlist + JWT auth and gates the entire /admin/* surface
 * from an operator's perspective). The issue use-case mints a key;
 * the revoke use-case invalidates it. Both pin their audit trail
 * + error paths.
 */

import { IssueAdminApiKeyUseCase } from '../src/administration/application/use-cases/issue-admin-api-key.use-case';
import { RevokeAdminApiKeyUseCase } from '../src/administration/application/use-cases/revoke-admin-api-key.use-case';
import { Test, TestingModule } from '@nestjs/testing';
import { PublicTestModule } from './public-test.module';
import {
  teardown,
} from './harness';

describe('Admin API key lifecycle (integration)', () => {
  let module: TestingModule;
  let issueUc: IssueAdminApiKeyUseCase;
  let revokeUc: RevokeAdminApiKeyUseCase;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [PublicTestModule],
    }).compile();
    issueUc = module.get(IssueAdminApiKeyUseCase);
    revokeUc = module.get(RevokeAdminApiKeyUseCase);
  });

  afterAll(async () => {
    await module.close();
    await teardown();
  });

  it('issues a key + revokes it idempotently', async () => {
    // 1. Issue.
    const issued = await issueUc.execute({
      name: 'ci-test-key',
      createdBy: 'ci@cerberus.local',
      ttlSeconds: 3600,
    });
    expect(issued.key.id).toBeTruthy();
    expect(issued.plaintextToken).toBeTruthy();
    expect(issued.key.role.value).toBe('ADMIN');
    expect(issued.key.revokedAt).toBeNull();

    // 2. First revoke — succeeds.
    await revokeUc.execute(issued.key.id);

    // 3. Second revoke — idempotent (no throw, just no-op).
    await revokeUc.execute(issued.key.id);
  });

  it('rejects invalid ttlSeconds', async () => {
    await expect(
      issueUc.execute({
        name: 'bad-ttl',
        createdBy: 'ci@cerberus.local',
        ttlSeconds: 0,
      }),
    ).rejects.toMatchObject({
      code: 'admin.api_key.ttl_non_positive',
    });
  });

  it('rejects an unknown keyId on revoke', async () => {
    await expect(
      revokeUc.execute('00000000-0000-4000-8000-000000000000'),
    ).rejects.toMatchObject({
      code: 'admin.api_key.not_found',
    });
  });
});