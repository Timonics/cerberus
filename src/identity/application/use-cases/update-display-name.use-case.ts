import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { User } from '../../domain/aggregates/user';
import { UserId } from '../../domain/value-objects/user-id';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../domain/ports/user.repository.port';

export interface UpdateDisplayNameInput {
  userId: string;
  /**
   * New display name. `null` clears the name.
   * Caller (controller) is responsible for ensuring this matches the
   * intent expressed by `clearDisplayName`.
   */
  displayName: string | null;
}

export interface UpdateDisplayNameResult {
  userId: string;
  displayName: string | null;
}

/**
 * Update the calling user's display name.
 *
 * Loads the user aggregate, calls `User.changeDisplayName` (which enforces
 * the 120-char cap and produces an updated instance), persists, and
 * returns the new value.
 *
 * Does NOT emit a domain event — display-name changes are not
 * security-relevant and don't trigger session invalidation.
 */
@Injectable()
export class UpdateDisplayNameUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
  ) {}

  public async execute(
    input: UpdateDisplayNameInput,
  ): Promise<UpdateDisplayNameResult> {
    const userId = UserId.create(input.userId);

    const updated = await this.txRunner.run<{ displayName: string | null }>(
      async (tx: Tx) => {
        const user = await this.userRepo.findById(tx, userId);
        if (!user) {
          throw new DomainError(
            'identity.user.not_found',
            'User does not exist',
            { userId: userId.value },
          );
        }
        const next: User = user.changeDisplayName(
          this.clock,
          input.displayName,
        );
        await this.userRepo.save(tx, next);
        return { displayName: next.displayName };
      },
    );

    return { userId: userId.value, displayName: updated.displayName };
  }
}
