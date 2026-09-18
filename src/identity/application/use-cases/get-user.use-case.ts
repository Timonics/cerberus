import { Inject, Injectable } from '@nestjs/common';
import {
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
} from '../../../shared/domain';
import { UserId } from '../../domain/value-objects/user-id';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../domain/ports/membership.repository.port';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../domain/ports/mfa-secret.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';

export interface GetUserInput {
  userId: string;
}

export interface GetUserResult {
  userId: string;
  organizationId: string;
  email: string;
  displayName: string | null;
  emailVerified: boolean;
  mfaEnabled: boolean;
  role: string;
  createdAt: Date;
}

/**
 * Read-side use-case: fetch a user profile + membership + MFA status.
 *
 * Used by the admin endpoints and by the "my profile" endpoint.
 * Not security-sensitive — returns non-secret data only.
 */
@Injectable()
export class GetUserUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
  ) {}

  public async execute(input: GetUserInput): Promise<GetUserResult> {
    const userId = UserId.create(input.userId);

    return this.txRunner.run(async (tx) => {
      const user = await this.userRepo.findById(tx, userId);
      if (!user) {
        throw new DomainError(
          'identity.user.not_found',
          'User does not exist',
          { userId: userId.value },
        );
      }
      const membership = await this.membershipRepo.findByUserId(tx, userId);
      const mfa = await this.mfaRepo.findById(tx, userId);

      return {
        userId: user.id.value,
        organizationId: user.organizationId.value,
        email: user.email.value,
        displayName: user.displayName,
        emailVerified: user.isEmailVerified(),
        mfaEnabled: Boolean(mfa?.confirmed),
        role: membership?.role.toString() ?? 'MEMBER',
        createdAt: user.createdAt,
      };
    });
  }
}
