import { BaseRepository } from '../../../shared/domain';
import { MfaSecret } from '../aggregates/mfa-secret';
import { UserId } from '../value-objects/user-id';

/**
 * MfaSecret repository port.
 *
 * Owns the `mfa_secrets` and `recovery_codes` tables. The repository
 * loads both together so the aggregate has its full state. The MFA
 * secret has a 1:1 relationship with users and a 1:N relationship with
 * recovery codes — both owned by this aggregate.
 *
 * On `delete()`, BOTH the secret AND its recovery codes are removed
 * (the FK cascade enforces this at the DB level).
 */
export abstract class MfaSecretRepository extends BaseRepository<
  MfaSecret,
  UserId
> {
  // Inherits findById(tx, UserId), save(tx, MfaSecret), delete(tx, UserId).
  //
  // `delete` is used when MFA is disabled entirely.
  //
  // Save handles both pending and confirmed states — the aggregate's
  // `confirmed` flag is what distinguishes them, and the recovery codes
  // are persisted alongside the secret in the same call.
}

export const MFA_SECRET_REPOSITORY = Symbol('MfaSecretRepository');
