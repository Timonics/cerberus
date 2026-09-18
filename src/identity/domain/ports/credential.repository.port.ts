import { BaseRepository } from '../../../shared/domain';
import { Credential } from '../aggregates/credential';
import { UserId } from '../value-objects/user-id';

/**
 * Credential repository port.
 *
 * Owns the `credentials` table. The relationship is one-to-one with
 * `users` (each user has exactly one credential row) — there's a UNIQUE
 * constraint on `userId` at the DB level.
 */
export abstract class CredentialRepository extends BaseRepository<
  Credential,
  UserId
> {
  // Inherits findById(tx, UserId) and save(tx, Credential) from base.
  // The delete method is reserved for GDPR hard-delete flows; we never
  // call it from regular use-cases.
}

export const CREDENTIAL_REPOSITORY = Symbol('CredentialRepository');
